# Copyright 2014 Rackspace US, Inc
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

from cryptography import exceptions as crypto_exceptions
from cryptography.hazmat import backends
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from oslo_config import cfg
from oslo_config import fixture as oslo_fixture
from oslo_utils import timeutils

import octavia.certificates.generator.local as local_cert_gen
from octavia.common import exceptions
from octavia.tests.unit.certificates.generator import local_csr


class TestLocalGenerator(local_csr.BaseLocalCSRTestCase):
    def setUp(self):
        super().setUp()
        self.conf = self.useFixture(oslo_fixture.Config(cfg.CONF))
        self.conf.config(group='certificates', key_algorithm='RSA-2048')
        self.signing_digest = "sha256"

        # Setup CA data

        ca_cert = x509.CertificateBuilder()
        valid_from_datetime = timeutils.utcnow()
        valid_until_datetime = (timeutils.utcnow() +
                                datetime.timedelta(
            seconds=2 * 365 * 24 * 60 * 60))
        ca_cert = ca_cert.not_valid_before(valid_from_datetime)
        ca_cert = ca_cert.not_valid_after(valid_until_datetime)
        ca_cert = ca_cert.serial_number(1)
        subject_name = x509.Name([
            x509.NameAttribute(x509.oid.NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(x509.oid.NameOID.STATE_OR_PROVINCE_NAME,
                               "Oregon"),
            x509.NameAttribute(x509.oid.NameOID.LOCALITY_NAME, "Springfield"),
            x509.NameAttribute(x509.oid.NameOID.ORGANIZATION_NAME,
                               "Springfield Nuclear Power Plant"),
            x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "maggie1"),
        ])
        ca_cert = ca_cert.subject_name(subject_name)
        ca_cert = ca_cert.issuer_name(subject_name)
        ca_cert = ca_cert.public_key(self.ca_key.public_key())
        signed_cert = ca_cert.sign(private_key=self.ca_key,
                                   algorithm=hashes.SHA256(),
                                   backend=backends.default_backend())

        self.ca_certificate = signed_cert.public_bytes(
            encoding=serialization.Encoding.PEM)

        self.cert_generator = local_cert_gen.LocalCertGenerator

    def test_sign_cert(self):
        # Attempt sign a cert
        signed_cert = self.cert_generator.sign_cert(
            csr=self.certificate_signing_request,
            validity=2 * 365 * 24 * 60 * 60,
            ca_cert=self.ca_certificate,
            ca_key=self.ca_private_key,
            ca_key_pass=self.ca_private_key_passphrase,
            ca_digest=self.signing_digest
        )

        self.assertIn("-----BEGIN CERTIFICATE-----",
                      signed_cert.decode('ascii'))

        # Load the cert for specific tests
        cert = x509.load_pem_x509_certificate(
            data=signed_cert, backend=backends.default_backend())

        # Make sure expiry time is accurate
        should_expire = (timeutils.utcnow() +
                         datetime.timedelta(seconds=2 * 365 * 24 * 60 * 60))
        diff = should_expire - cert.not_valid_after
        self.assertLess(diff, datetime.timedelta(seconds=10))

        # Make sure this is a version 3 X509.
        self.assertEqual('v3', cert.version.name)

        # Make sure this cert is marked as Server and Client Cert via the
        # extended Key Usage extension
        self.assertIn(x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
                      cert.extensions.get_extension_for_class(
                          x509.ExtendedKeyUsage).value._usages)
        self.assertIn(x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
                      cert.extensions.get_extension_for_class(
                          x509.ExtendedKeyUsage).value._usages)

        # Make sure this cert can't sign other certs
        self.assertFalse(cert.extensions.get_extension_for_class(
            x509.BasicConstraints).value.ca)

        # Make sure SubjectKeyIdentifier extension is present
        ski = cert.extensions.get_extension_for_class(
            x509.SubjectKeyIdentifier)
        self.assertIsNotNone(ski.value.digest)
        self.assertFalse(ski.critical)

        # Make sure AuthorityKeyIdentifier extension is present
        aki = cert.extensions.get_extension_for_class(
            x509.AuthorityKeyIdentifier)
        self.assertIsNotNone(aki.value.key_identifier)
        self.assertFalse(aki.critical)

    def test_sign_cert_passphrase_none(self):
        # Attempt sign a cert
        ca_private_key = self.ca_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        signed_cert = self.cert_generator.sign_cert(
            csr=self.certificate_signing_request,
            validity=2 * 365 * 24 * 60 * 60,
            ca_cert=self.ca_certificate,
            ca_key=ca_private_key,
            ca_key_pass=None,
            ca_digest=self.signing_digest
        )

        self.assertIn("-----BEGIN CERTIFICATE-----",
                      signed_cert.decode('ascii'))

        # Load the cert for specific tests
        cert = x509.load_pem_x509_certificate(
            data=signed_cert, backend=backends.default_backend())

        # Make sure expiry time is accurate
        should_expire = (timeutils.utcnow() +
                         datetime.timedelta(seconds=2 * 365 * 24 * 60 * 60))
        diff = should_expire - cert.not_valid_after
        self.assertLess(diff, datetime.timedelta(seconds=10))

        # Make sure this is a version 3 X509.
        self.assertEqual('v3', cert.version.name)

        # Make sure this cert is marked as Server and Client Cert via the
        # extended Key Usage extension
        self.assertIn(x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
                      cert.extensions.get_extension_for_class(
                          x509.ExtendedKeyUsage).value._usages)
        self.assertIn(x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
                      cert.extensions.get_extension_for_class(
                          x509.ExtendedKeyUsage).value._usages)

        # Make sure this cert can't sign other certs
        self.assertFalse(cert.extensions.get_extension_for_class(
            x509.BasicConstraints).value.ca)

        # Make sure SubjectKeyIdentifier extension is present
        ski = cert.extensions.get_extension_for_class(
            x509.SubjectKeyIdentifier)
        self.assertIsNotNone(ski.value.digest)
        self.assertFalse(ski.critical)

        # Make sure AuthorityKeyIdentifier extension is present
        aki = cert.extensions.get_extension_for_class(
            x509.AuthorityKeyIdentifier)
        self.assertIsNotNone(aki.value.key_identifier)
        self.assertFalse(aki.critical)

    def test_sign_cert_invalid_algorithm(self):
        self.assertRaises(
            crypto_exceptions.UnsupportedAlgorithm,
            self.cert_generator.sign_cert,
            csr=self.certificate_signing_request,
            validity=2 * 365 * 24 * 60 * 60,
            ca_cert=self.ca_certificate,
            ca_key=self.ca_private_key,
            ca_key_pass=self.ca_private_key_passphrase,
            ca_digest='not_an_algorithm'
        )

    def test_generate_cert_key_pair(self):
        cn = 'testCN'
        bit_length = 1024

        with mock.patch(
                'octavia.common.tls_utils.pqc_utils'
                '.check_algorithm_compliance'):
            cert_object = self.cert_generator.generate_cert_key_pair(
                cn=cn,
                validity=2 * 365 * 24 * 60 * 60,
                bit_length=bit_length,
                passphrase=self.ca_private_key_passphrase,
                ca_cert=self.ca_certificate,
                ca_key=self.ca_private_key,
                ca_key_pass=self.ca_private_key_passphrase
            )

        cert = x509.load_pem_x509_certificate(
            data=cert_object.certificate, backend=backends.default_backend())
        self.assertIsNotNone(cert)

        key = serialization.load_pem_private_key(
            data=cert_object.private_key,
            password=cert_object.private_key_passphrase,
            backend=backends.default_backend())
        self.assertIsNotNone(key)

    def test_generate_private_key_rsa_2048(self):
        self.conf.config(group='certificates', key_algorithm='RSA-2048')
        pk_pem = self.cert_generator._generate_private_key()
        pk = serialization.load_pem_private_key(
            pk_pem, password=None, backend=backends.default_backend())
        self.assertIsInstance(pk, rsa.RSAPrivateKey)
        self.assertEqual(2048, pk.key_size)

    def test_generate_private_key_rsa_4096(self):
        self.conf.config(group='certificates', key_algorithm='RSA-4096')
        pk_pem = self.cert_generator._generate_private_key()
        pk = serialization.load_pem_private_key(
            pk_pem, password=None, backend=backends.default_backend())
        self.assertIsInstance(pk, rsa.RSAPrivateKey)
        self.assertEqual(4096, pk.key_size)

    def test_generate_private_key_ecdsa_p256(self):
        self.conf.config(group='certificates', key_algorithm='ECDSA-P256')
        pk_pem = self.cert_generator._generate_private_key()
        pk = serialization.load_pem_private_key(
            pk_pem, password=None, backend=backends.default_backend())
        self.assertIsInstance(pk, ec.EllipticCurvePrivateKey)
        self.assertIsInstance(pk.curve, ec.SECP256R1)

    def test_generate_private_key_ecdsa_p384(self):
        self.conf.config(group='certificates', key_algorithm='ECDSA-P384')
        pk_pem = self.cert_generator._generate_private_key()
        pk = serialization.load_pem_private_key(
            pk_pem, password=None, backend=backends.default_backend())
        self.assertIsInstance(pk, ec.EllipticCurvePrivateKey)
        self.assertIsInstance(pk.curve, ec.SECP384R1)

    def test_generate_private_key_unsupported_raises(self):
        self.conf.config(group='certificates', key_algorithm='NOT-REAL')
        self.assertRaises(
            exceptions.ConfigInvalidError,
            self.cert_generator._generate_private_key)

    def test_generate_csr_rsa_key_usage(self):
        self.conf.config(group='certificates', key_algorithm='RSA-2048')
        pk_pem = self.cert_generator._generate_private_key()
        csr_pem = self.cert_generator._generate_csr('testcn', pk_pem)
        csr = x509.load_pem_x509_csr(csr_pem, backends.default_backend())
        ku = csr.extensions.get_extension_for_class(x509.KeyUsage).value
        self.assertTrue(ku.digital_signature)
        self.assertTrue(ku.key_encipherment)
        self.assertFalse(ku.key_agreement)

    def test_generate_csr_ecdsa_key_usage(self):
        self.conf.config(group='certificates', key_algorithm='ECDSA-P256')
        pk_pem = self.cert_generator._generate_private_key()
        csr_pem = self.cert_generator._generate_csr('testcn', pk_pem)
        csr = x509.load_pem_x509_csr(csr_pem, backends.default_backend())
        ku = csr.extensions.get_extension_for_class(x509.KeyUsage).value
        self.assertTrue(ku.digital_signature)
        self.assertFalse(ku.key_encipherment)
        self.assertTrue(ku.key_agreement)
