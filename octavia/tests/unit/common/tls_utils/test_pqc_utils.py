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
import datetime
from unittest import mock

from cryptography.hazmat import backends
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from oslo_config import cfg
from oslo_config import fixture as oslo_fixture

from octavia.common import constants
from octavia.common import exceptions
from octavia.common.tls_utils import pqc_utils
from octavia.tests.unit import base


def _make_rsa_cert(key_size=2048):
    """Generate a self-signed RSA certificate for testing."""
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=backends.default_backend()
    )
    subject = x509.Name([
        x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, 'test'),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256(), backends.default_backend())
    )
    return cert


def _make_ec_cert(curve=None):
    """Generate a self-signed EC certificate for testing."""
    curve = curve or ec.SECP256R1()
    key = ec.generate_private_key(curve, backends.default_backend())
    subject = x509.Name([
        x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, 'test'),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256(), backends.default_backend())
    )
    return cert


class TestExtractAlgorithmName(base.TestCase):
    def test_rsa_2048(self):
        key = rsa.generate_private_key(
            65537, 2048, backends.default_backend()).public_key()
        self.assertEqual('RSA-2048', pqc_utils._extract_algorithm_name(key))

    def test_rsa_4096(self):
        key = rsa.generate_private_key(
            65537, 4096, backends.default_backend()).public_key()
        self.assertEqual('RSA-4096', pqc_utils._extract_algorithm_name(key))

    def test_ecdsa_p256(self):
        key = ec.generate_private_key(
            ec.SECP256R1(), backends.default_backend()).public_key()
        self.assertEqual('ECDSA-P256', pqc_utils._extract_algorithm_name(key))

    def test_ecdsa_p384(self):
        key = ec.generate_private_key(
            ec.SECP384R1(), backends.default_backend()).public_key()
        self.assertEqual('ECDSA-P384', pqc_utils._extract_algorithm_name(key))

    def test_unknown_key_type(self):
        mock_key = mock.MagicMock(spec=[])
        self.assertEqual(
            'UNKNOWN', pqc_utils._extract_algorithm_name(mock_key))


class TestCheckAlgorithmCompliance(base.TestCase):

    def setUp(self):
        super().setUp()
        self.conf = self.useFixture(oslo_fixture.Config(cfg.CONF))
        self.rsa_cert = _make_rsa_cert()
        self.ec_cert = _make_ec_cert()

    def _set_modes(self, control=constants.PQC_DISABLED,
                   data=constants.PQC_DISABLED,
                   allowed=None):
        if allowed is None:
            allowed = list(constants.PQC_SAFE_ALGORITHMS)
        self.conf.config(group='certificates',
                         pqc_control_plane_check_mode=control)
        self.conf.config(group='certificates',
                         pqc_data_plane_check_mode=data)
        self.conf.config(group='certificates',
                         pqc_allowed_algorithms=allowed)

    def test_disabled_control_plane_no_check(self):
        self._set_modes(control=constants.PQC_DISABLED)
        algo, compliant = pqc_utils.check_algorithm_compliance(
            self.rsa_cert, 'control')
        self.assertIsNone(algo)
        self.assertTrue(compliant)

    def test_disabled_data_plane_no_check(self):
        self._set_modes(data=constants.PQC_DISABLED)
        algo, compliant = pqc_utils.check_algorithm_compliance(
            self.rsa_cert, 'data')
        self.assertIsNone(algo)
        self.assertTrue(compliant)

    def test_permissive_compliant_no_warning(self):
        self._set_modes(data=constants.PQC_PERMISSIVE,
                        allowed=['RSA-2048'])
        with mock.patch.object(pqc_utils.LOG, 'warning') as mock_warn:
            algo, compliant = pqc_utils.check_algorithm_compliance(
                self.rsa_cert, 'data')
        self.assertEqual('RSA-2048', algo)
        self.assertTrue(compliant)
        mock_warn.assert_not_called()

    def test_permissive_noncompliant_emits_warning(self):
        self._set_modes(data=constants.PQC_PERMISSIVE)
        with mock.patch.object(pqc_utils.LOG, 'warning') as mock_warn:
            algo, compliant = pqc_utils.check_algorithm_compliance(
                self.rsa_cert, 'data')
        self.assertEqual('RSA-2048', algo)
        self.assertFalse(compliant)
        mock_warn.assert_called_once()
        call_args = mock_warn.call_args[0]
        self.assertIn('RSA-2048', str(call_args))

    def test_strict_compliant_no_exception(self):
        self._set_modes(data=constants.PQC_STRICT,
                        allowed=['RSA-2048'])
        algo, compliant = pqc_utils.check_algorithm_compliance(
            self.rsa_cert, 'data')
        self.assertEqual('RSA-2048', algo)
        self.assertTrue(compliant)

    def test_strict_noncompliant_raises(self):
        self._set_modes(data=constants.PQC_STRICT)
        self.assertRaises(
            exceptions.CertificateValidationException,
            pqc_utils.check_algorithm_compliance,
            self.rsa_cert, 'data')

    def test_strict_noncompliant_control_plane_raises(self):
        self._set_modes(control=constants.PQC_STRICT)
        self.assertRaises(
            exceptions.CertificateValidationException,
            pqc_utils.check_algorithm_compliance,
            self.rsa_cert, 'control')

    def test_accepts_public_key_directly(self):
        self._set_modes(data=constants.PQC_PERMISSIVE)
        pub_key = self.rsa_cert.public_key()
        with mock.patch.object(pqc_utils.LOG, 'warning'):
            algo, compliant = pqc_utils.check_algorithm_compliance(
                pub_key, 'data')
        self.assertEqual('RSA-2048', algo)
        self.assertFalse(compliant)

    def test_ec_cert_name_extraction(self):
        self._set_modes(data=constants.PQC_PERMISSIVE)
        with mock.patch.object(pqc_utils.LOG, 'warning'):
            algo, compliant = pqc_utils.check_algorithm_compliance(
                self.ec_cert, 'data')
        self.assertEqual('ECDSA-P256', algo)
        self.assertFalse(compliant)

    def test_permissive_warning_contains_plane(self):
        self._set_modes(data=constants.PQC_PERMISSIVE)
        with mock.patch.object(pqc_utils.LOG, 'warning') as mock_warn:
            pqc_utils.check_algorithm_compliance(self.rsa_cert, 'data')
        call_kwargs = mock_warn.call_args[0]
        self.assertIn('data', str(call_kwargs))


class TestValidatePQCConfig(base.TestCase):

    def setUp(self):
        super().setUp()
        self.conf = self.useFixture(oslo_fixture.Config(cfg.CONF))

    def _set_config(self, control=constants.PQC_DISABLED,
                    data=constants.PQC_DISABLED,
                    allowed=None, key_algo='RSA-2048'):
        if allowed is None:
            allowed = list(constants.PQC_SAFE_ALGORITHMS)
        self.conf.config(group='certificates',
                         pqc_control_plane_check_mode=control)
        self.conf.config(group='certificates',
                         pqc_data_plane_check_mode=data)
        self.conf.config(group='certificates',
                         pqc_allowed_algorithms=allowed)
        self.conf.config(group='certificates', key_algorithm=key_algo)

    def test_both_disabled_no_warning_even_if_lists_differ(self):
        extra_algo = list(constants.PQC_SAFE_ALGORITHMS) + ['CUSTOM-ALG']
        self._set_config(allowed=extra_algo)
        with mock.patch.object(pqc_utils.LOG, 'warning') as mock_warn:
            pqc_utils.validate_pqc_config()
        mock_warn.assert_not_called()

    def test_lists_identical_no_warning(self):
        self._set_config(data=constants.PQC_PERMISSIVE)
        with mock.patch.object(pqc_utils.LOG, 'warning') as mock_warn:
            pqc_utils.validate_pqc_config()
        mock_warn.assert_not_called()

    def test_added_algo_emits_warning(self):
        extra = list(constants.PQC_SAFE_ALGORITHMS) + ['CUSTOM-ALG']
        self._set_config(data=constants.PQC_PERMISSIVE, allowed=extra)
        with mock.patch.object(pqc_utils.LOG, 'warning') as mock_warn:
            pqc_utils.validate_pqc_config()
        mock_warn.assert_called_once()
        warning_text = str(mock_warn.call_args)
        self.assertIn('CUSTOM-ALG', warning_text)
        self.assertIn('Added', warning_text)

    def test_removed_algo_emits_warning(self):
        reduced = [a for a in constants.PQC_SAFE_ALGORITHMS
                   if a != 'ML-DSA-44']
        self._set_config(data=constants.PQC_PERMISSIVE, allowed=reduced)
        with mock.patch.object(pqc_utils.LOG, 'warning') as mock_warn:
            pqc_utils.validate_pqc_config()
        mock_warn.assert_called_once()
        warning_text = str(mock_warn.call_args)
        self.assertIn('ML-DSA-44', warning_text)
        self.assertIn('Removed', warning_text)

    def test_added_and_removed_emits_single_warning(self):
        modified = ([a for a in constants.PQC_SAFE_ALGORITHMS
                     if a != 'ML-DSA-44'] + ['CUSTOM-ALG'])
        self._set_config(data=constants.PQC_PERMISSIVE, allowed=modified)
        with mock.patch.object(pqc_utils.LOG, 'warning') as mock_warn:
            pqc_utils.validate_pqc_config()
        self.assertEqual(1, mock_warn.call_count)
        warning_text = str(mock_warn.call_args)
        self.assertIn('ML-DSA-44', warning_text)
        self.assertIn('CUSTOM-ALG', warning_text)

    def test_strict_control_key_algo_in_allowlist_no_error(self):
        self._set_config(
            control=constants.PQC_STRICT,
            allowed=['ML-DSA-65'],
            key_algo='ML-DSA-65')
        with mock.patch.object(pqc_utils.LOG, 'warning'):
            pqc_utils.validate_pqc_config()

    def test_strict_control_key_algo_not_in_allowlist_raises(self):
        self._set_config(
            control=constants.PQC_STRICT,
            allowed=['ML-DSA-65'],
            key_algo='RSA-2048')
        self.assertRaises(
            exceptions.ConfigInvalidError,
            pqc_utils.validate_pqc_config)

    def test_permissive_control_key_algo_mismatch_no_error(self):
        self._set_config(
            control=constants.PQC_PERMISSIVE,
            allowed=['ML-DSA-65'],
            key_algo='RSA-2048')
        with mock.patch.object(pqc_utils.LOG, 'warning'):
            pqc_utils.validate_pqc_config()


class TestValidatePQCConfigStartup(base.TestCase):
    """Tests for startup validation of control-plane STRICT mode."""

    def setUp(self):
        super().setUp()
        self.conf = self.useFixture(oslo_fixture.Config(cfg.CONF))

    def test_startup_strict_control_invalid_key_algo_raises(self):
        self.conf.config(group='certificates',
                         pqc_control_plane_check_mode=constants.PQC_STRICT)
        self.conf.config(group='certificates',
                         pqc_data_plane_check_mode=constants.PQC_DISABLED)
        self.conf.config(group='certificates',
                         pqc_allowed_algorithms=['ML-DSA-65'])
        self.conf.config(group='certificates', key_algorithm='RSA-2048')
        self.assertRaises(
            exceptions.ConfigInvalidError,
            pqc_utils.validate_pqc_config)

    def test_startup_strict_control_valid_key_algo_no_error(self):
        self.conf.config(group='certificates',
                         pqc_control_plane_check_mode=constants.PQC_STRICT)
        self.conf.config(group='certificates',
                         pqc_data_plane_check_mode=constants.PQC_DISABLED)
        self.conf.config(group='certificates',
                         pqc_allowed_algorithms=['ML-DSA-65'])
        self.conf.config(group='certificates', key_algorithm='ML-DSA-65')
        with mock.patch.object(pqc_utils.LOG, 'warning'):
            pqc_utils.validate_pqc_config()

    def test_startup_both_disabled_no_validation_of_key_algo(self):
        self.conf.config(group='certificates',
                         pqc_control_plane_check_mode=constants.PQC_DISABLED)
        self.conf.config(group='certificates',
                         pqc_data_plane_check_mode=constants.PQC_DISABLED)
        self.conf.config(group='certificates',
                         pqc_allowed_algorithms=['ML-DSA-65'])
        self.conf.config(group='certificates', key_algorithm='RSA-2048')
        pqc_utils.validate_pqc_config()

    def _make_key_pem(self, key):
        return key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption())
