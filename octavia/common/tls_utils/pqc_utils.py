# Copyright 2024 OpenStack Contributors
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from oslo_config import cfg
from oslo_log import log as logging

from octavia.common import constants
from octavia.common import exceptions

CONF = cfg.CONF
LOG = logging.getLogger(__name__)

_EC_CURVE_NAMES = {
    'secp256r1': 'ECDSA-P256',
    'secp384r1': 'ECDSA-P384',
}


def _extract_algorithm_name(key):
    """Return a canonical algorithm name string from a public key object.

    :param key: a pyca/cryptography public key object
    :returns: canonical algorithm name string, e.g. 'RSA-2048', 'ECDSA-P256'
    """
    if isinstance(key, rsa.RSAPublicKey):
        return 'RSA-%d' % key.key_size
    if isinstance(key, ec.EllipticCurvePublicKey):
        curve_name = key.curve.name
        return _EC_CURVE_NAMES.get(curve_name, 'ECDSA-%s' % curve_name)
    return 'UNKNOWN'


def check_algorithm_compliance(cert_or_key, plane):
    """Check whether cert_or_key satisfies the configured PQC policy.

    Reads the per-plane check mode from config and acts accordingly:

    * DISABLED  — returns immediately, no check performed.
    * PERMISSIVE — emits LOG.warning when algorithm is not in the
                   allowed list; processing continues normally.
    * STRICT    — raises CertificateValidationException when algorithm
                  is not in the allowed list.

    :param cert_or_key: pyca/cryptography X509 Certificate or public key
    :param plane: 'control' or 'data'
    :returns: (algorithm_name, is_compliant) tuple; algorithm_name is None
              when mode is DISABLED
    :raises exceptions.CertificateValidationException: in STRICT mode when
        the algorithm is not in pqc_allowed_algorithms
    """
    if plane == 'control':
        mode = CONF.certificates.pqc_control_plane_check_mode
    else:
        mode = CONF.certificates.pqc_data_plane_check_mode

    if mode == constants.PQC_DISABLED:
        return (None, True)

    if isinstance(cert_or_key, x509.Certificate):
        key = cert_or_key.public_key()
    else:
        key = cert_or_key

    algorithm_name = _extract_algorithm_name(key)
    allowed = CONF.certificates.pqc_allowed_algorithms
    is_compliant = algorithm_name in allowed

    if not is_compliant:
        if mode == constants.PQC_PERMISSIVE:
            LOG.warning(
                'Certificate uses algorithm %s which is not in the PQC '
                'allowed list for the %s plane. '
                'See the PQC Migration operator guide.',
                algorithm_name, plane)
        elif mode == constants.PQC_STRICT:
            raise exceptions.CertificateValidationException(
                algorithm=algorithm_name, plane=plane)

    return (algorithm_name, is_compliant)


def validate_pqc_config():
    """Validate PQC configuration at service startup.

    Must be called once after oslo.config is fully loaded, from each
    Octavia service entrypoint.

    Performs two checks:

    1. Algorithm list audit: when at least one plane is non-DISABLED,
       compares the configured pqc_allowed_algorithms against the
       Octavia-maintained PQC_SAFE_ALGORITHMS constant and emits a
       LOG.warning describing any differences.

    2. Control-plane consistency: when pqc_control_plane_check_mode is
       STRICT, verifies that key_algorithm is present in the effective
       pqc_allowed_algorithms list.  Raises ConfigInvalidError if not,
       so the service fails fast at startup rather than mid-operation.

    :raises exceptions.ConfigInvalidError: when pqc_control_plane_check_mode
        is STRICT and key_algorithm is not in pqc_allowed_algorithms
    """
    control_mode = CONF.certificates.pqc_control_plane_check_mode
    data_mode = CONF.certificates.pqc_data_plane_check_mode

    if (control_mode != constants.PQC_DISABLED or
            data_mode != constants.PQC_DISABLED):
        configured = set(CONF.certificates.pqc_allowed_algorithms)
        defaults = set(constants.PQC_SAFE_ALGORITHMS)
        added = sorted(configured - defaults)
        removed = sorted(defaults - configured)
        if added or removed:
            LOG.warning(
                'PQC allowed algorithm list differs from Octavia defaults.\n'
                '  Added (not in Octavia defaults): %s\n'
                '  Removed (from Octavia defaults): %s\n'
                '  Effective list: %s\n'
                '  See the PQC Migration operator guide for the rationale '
                'behind the Octavia default list.',
                added, removed,
                sorted(CONF.certificates.pqc_allowed_algorithms))

    if control_mode == constants.PQC_STRICT:
        key_algo = CONF.certificates.key_algorithm
        allowed = CONF.certificates.pqc_allowed_algorithms
        if key_algo not in allowed:
            raise exceptions.ConfigInvalidError(
                msg=('pqc_control_plane_check_mode is STRICT but '
                     'key_algorithm=%r is not in pqc_allowed_algorithms %s. '
                     'Service cannot start.' % (key_algo, allowed)))
