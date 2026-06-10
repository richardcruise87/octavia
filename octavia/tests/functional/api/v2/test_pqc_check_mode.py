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

from unittest import mock

from oslo_utils import uuidutils

from octavia.common import constants
from octavia.common import exceptions
from octavia.tests.common import sample_certs
from octavia.tests.functional.api.v2 import base


class TestPQCDataPlaneCheckMode(base.BaseAPITest):
    """Functional tests for PQC data-plane check mode on listener TLS.

    These tests verify that the three check modes (DISABLED, PERMISSIVE,
    STRICT) produce the correct API responses and log behaviour when a
    listener is created with a TLS certificate.

    Because Barbican is mocked in the functional test environment, the
    pqc_utils.check_algorithm_compliance function is also mocked at the
    points it is called from the API request path.
    """

    root_tag = 'listener'
    root_tag_list = 'listeners'
    root_tag_links = 'listeners_links'

    def setUp(self):
        super().setUp()
        self.lb = self.create_load_balancer(uuidutils.generate_uuid())
        self.lb_id = self.lb.get('loadbalancer').get('id')
        self.project_id = self.lb.get('loadbalancer').get('project_id')
        self.set_lb_status(self.lb_id)

        tls_cert_mock = mock.MagicMock()
        tls_cert_mock.get_certificate.return_value = sample_certs.X509_CERT
        tls_cert_mock.get_private_key.return_value = sample_certs.X509_CERT_KEY
        tls_cert_mock.get_private_key_passphrase.return_value = None
        tls_cert_mock.get_intermediates.return_value = None
        self.cert_manager_mock().get_cert.return_value = tls_cert_mock

        self.tls_ref = uuidutils.generate_uuid()

    def _listener_body(self, port=80):
        return self._build_body({
            'protocol': constants.PROTOCOL_TERMINATED_HTTPS,
            'protocol_port': port,
            'loadbalancer_id': self.lb_id,
            'project_id': self.project_id,
            'default_tls_container_ref': self.tls_ref,
        })

    def test_create_listener_rsa_cert_disabled(self):
        self.conf.config(group='certificates',
                         pqc_data_plane_check_mode=constants.PQC_DISABLED)
        response = self.post(
            self.LISTENERS_PATH, self._listener_body(), status=201)
        self.assertIn('PENDING_CREATE', str(response.json))

    def test_create_listener_rsa_cert_permissive(self):
        self.conf.config(group='certificates',
                         pqc_data_plane_check_mode=constants.PQC_PERMISSIVE)
        warning_emitted = []

        def fake_check(cert_or_key, plane):
            warning_emitted.append((cert_or_key, plane))
            return ('RSA-2048', False)

        with mock.patch(
                'octavia.common.tls_utils.pqc_utils'
                '.check_algorithm_compliance',
                side_effect=fake_check):
            response = self.post(
                self.LISTENERS_PATH, self._listener_body(), status=201)
        self.assertIn('PENDING_CREATE', str(response.json))
        self.assertTrue(len(warning_emitted) >= 1,
                        'check_algorithm_compliance was not called in '
                        'PERMISSIVE mode')
        planes = [call[1] for call in warning_emitted]
        self.assertIn('data', planes)

    def test_create_listener_rsa_cert_strict_returns_400(self):
        self.conf.config(group='certificates',
                         pqc_data_plane_check_mode=constants.PQC_STRICT)

        def fake_check_strict(cert_or_key, plane):
            raise exceptions.CertificateValidationException(
                algorithm='RSA-2048', plane=plane)

        with mock.patch(
                'octavia.common.tls_utils.pqc_utils'
                '.check_algorithm_compliance',
                side_effect=fake_check_strict):
            response = self.post(
                self.LISTENERS_PATH, self._listener_body(),
                status=400, expect_errors=True)
        self.assertEqual(400, response.status_int)
        self.assertIn('RSA-2048', response.text)

    def test_update_listener_rsa_cert_strict_returns_400(self):
        self.conf.config(group='certificates',
                         pqc_data_plane_check_mode=constants.PQC_DISABLED)

        with mock.patch(
                'octavia.common.tls_utils.pqc_utils'
                '.check_algorithm_compliance'):
            listener = self.create_listener(
                constants.PROTOCOL_TERMINATED_HTTPS, 81, self.lb_id,
                default_tls_container_ref=self.tls_ref)
        listener_id = listener.get('listener').get('id')
        self.set_lb_status(self.lb_id)

        self.conf.config(group='certificates',
                         pqc_data_plane_check_mode=constants.PQC_STRICT)

        def fake_check_strict(cert_or_key, plane):
            raise exceptions.CertificateValidationException(
                algorithm='RSA-2048', plane=plane)

        update_body = self._build_body(
            {'default_tls_container_ref': uuidutils.generate_uuid()})
        with mock.patch(
                'octavia.common.tls_utils.pqc_utils'
                '.check_algorithm_compliance',
                side_effect=fake_check_strict):
            response = self.put(
                self.LISTENER_PATH.format(listener_id=listener_id),
                update_body, status=400, expect_errors=True)
        self.assertEqual(400, response.status_int)

    def test_create_http_listener_strict_unaffected(self):
        self.conf.config(group='certificates',
                         pqc_data_plane_check_mode=constants.PQC_STRICT)
        body = self._build_body({
            'protocol': constants.PROTOCOL_HTTP,
            'protocol_port': 82,
            'loadbalancer_id': self.lb_id,
            'project_id': self.project_id,
        })
        response = self.post(self.LISTENERS_PATH, body, status=201)
        self.assertIn('PENDING_CREATE', str(response.json))

    def test_create_listener_rsa_cert_strict_disabled_by_default(self):
        response = self.post(
            self.LISTENERS_PATH, self._listener_body(), status=201)
        self.assertIn('PENDING_CREATE', str(response.json))
