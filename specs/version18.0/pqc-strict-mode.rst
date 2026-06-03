..
 This work is licensed under a Creative Commons Attribution 3.0 Unported
 License.

 http://creativecommons.org/licenses/by/3.0/legalcode

=======================================
Post-Quantum Cryptography Strict Mode
=======================================

https://bugs.launchpad.net/octavia/+bug/2149791

Octavia's internal certificate infrastructure and TLS configuration paths
currently use classical asymmetric algorithms (RSA, ECDSA) that are vulnerable
to quantum attack via Shor's algorithm.  This spec introduces algorithm-agnostic
key generation and a configurable PQC strict mode, giving operators the tools to
audit existing deployments, enforce quantum-safe algorithm usage, and adopt
post-quantum algorithms as platform libraries expose them — without breaking
existing deployments.


Problem description
===================

Three related gaps combine to leave Octavia operators without a viable
post-quantum migration path:

**1. Hardcoded RSA key generation for amphora mTLS certificates.**

``LocalCertGenerator._generate_private_key()`` in
``octavia/certificates/generator/local.py`` unconditionally calls
``rsa.generate_private_key()`` with no configuration hook.  Every amphora
virtual machine receives an RSA-2048 certificate for the mutual TLS control
channel between the Octavia controller and the amphora agent.  There is no
supported way to change this algorithm without patching Octavia itself.

Per the OpenStack PQC assessment guide this is a CRITICAL finding: a
hardcoded quantum-vulnerable algorithm with no configuration option.

**2. No compliance checking on loaded certificates.**

When Octavia loads TLS certificates — whether user-provided certificates for
TERMINATED_HTTPS listeners, CA certificates for client authentication, pool
backend TLS certificates, or internally generated amphora mTLS certificates —
it performs no check on the public key algorithm in use.  Operators have no
automated mechanism to discover which of their deployed resources are using
quantum-vulnerable algorithms.

**3. No migration path or enforcement signal.**

Without a configurable strict mode and an operator-defined algorithm allowlist,
operators cannot enforce quantum-safe algorithm requirements or signal
programmatically that their deployment has completed the migration.  The lack of
enforcement makes compliance audits manual and error-prone.

Use cases:

* A deployer wants to begin migrating to PQC gradually.  They first enable
  warning mode to identify which resources carry quantum-vulnerable certificates,
  then migrate those resources, then enable strict enforcement.

* A deployer wants new amphora certificates to use ML-DSA once their platform's
  pyca/cryptography library supports it, without redeploying Octavia.

* A security auditor wants to verify that no TERMINATED_HTTPS listener in the
  deployment accepts traffic using a quantum-vulnerable certificate.


Proposed change
===============

Three coordinated parts, each independently deployable:

**Part 1 — Algorithm-agnostic key generation**

A new config option ``[certificates] key_algorithm`` (StrOpt) replaces the
hardcoded ``rsa.generate_private_key()`` call.  ``_generate_private_key()``
becomes a dispatch function that reads the configured algorithm name and
delegates entirely to pyca/cryptography — Octavia implements no cryptographic
primitives.

Initially supported values:

* ``RSA-2048`` (default, preserves current behaviour)
* ``RSA-4096``
* ``ECDSA-P256``
* ``ECDSA-P384``
* ``ML-DSA-44``, ``ML-DSA-65``, ``ML-DSA-87`` (available once
  pyca/cryptography exposes stable ML-DSA APIs — see Dependencies)

If the configured algorithm is not supported by the installed library version,
Octavia raises ``ConfigInvalidError`` at service startup with a message that
names the algorithm and the minimum library version required.  This fails fast
rather than silently falling back to a weaker algorithm.

The ``_generate_csr()`` function in the same file sets
``KeyUsage.key_encipherment = True`` unconditionally.  This is correct for RSA
(key transport) but violates RFC 5280 for ECDSA and ML-DSA keys, which require
only ``digital_signature`` (and ``key_agreement`` for ECDH-capable keys).  This
RFC 5280 compliance defect is corrected as part of this work item: ``KeyUsage``
is set based on the key type returned by the library.

**Part 2 — PQC compliance checker utility**

A new module ``octavia/common/tls_utils/pqc_utils.py`` exposes a single
public function::

    check_algorithm_compliance(public_key_or_cert) -> (algorithm_name, is_compliant)

The function accepts a pyca/cryptography public key or X.509 certificate
object, extracts the public key algorithm using the library's own introspection
APIs (``isinstance`` checks against library key classes, OID comparison for
PQC key types), and returns the detected algorithm name and whether it appears
in the operator-configured ``pqc_allowed_algorithms`` list.  The function
contains no custom OID tables or cryptographic logic — all algorithm knowledge
comes from pyca/cryptography.

The existing ``cert_parser.py`` public key comparison at line 61 uses
``.public_numbers()``, which is not available on ML-DSA and ML-KEM key objects.
This call is replaced with an algorithm-agnostic comparison using
``.public_bytes()`` serialisation, which works across all key types.

**Part 3 — PQC strict mode gate**

Two additional config options (``pqc_strict_mode`` and
``pqc_allowed_algorithms``) are added to the ``[certificates]`` group.  The
compliance checker from Part 2 is called at every certificate-load point in
Octavia:

.. csv-table:: Certificate load points
   :header: Load point, File, Trigger

   Amphora mTLS cert generation,octavia/certificates/generator/local.py,generate_cert_key_pair()
   Listener TLS cert (Barbican),octavia/certificates/manager/barbican.py,get_cert()
   Client-auth CA cert,octavia/api/v2/controllers/base.py,CA cert load
   Pool backend TLS cert,octavia/common/tls_utils/cert_parser.py,cert parse

When ``check_algorithm_compliance()`` returns ``is_compliant=False``:

* ``pqc_strict_mode = False``: emit ``LOG.warning`` with the certificate
  subject, detected algorithm name, and a reference to the operator migration
  guide.  Processing continues normally.

* ``pqc_strict_mode = True``: raise the existing
  ``exceptions.CertificateValidationException``.  API callers receive HTTP 400.
  The service refuses to configure the resource until the certificate is
  replaced with a compliant one.


Alternatives
------------

**Single ``cert_algorithm`` StrOpt with enumerated choices** (the approach
proposed in an AI-generated fix for bug #2149791): simpler, but addresses only
key generation and not compliance checking on loaded certificates.  It also
conflates algorithm selection with algorithm enforcement.  Rejected because it
solves only one of the three gaps described above.

**Auto-detect the strongest available algorithm at runtime**: Octavia queries
pyca/cryptography at startup and selects the strongest algorithm it finds.
Rejected because this creates implicit, deployment-specific behaviour that
complicates compliance audits.  Operators must be explicit about what algorithm
they intend to use; that intent belongs in configuration, not in heuristics.

**Separate ``[tls]`` configuration group**: The new options could be placed in
a dedicated ``[tls]`` group.  Rejected in favour of ``[certificates]`` because
all existing algorithm-related options (``signing_digest``,
``ca_private_key``, etc.) already live there, and the new options are
conceptually part of the same subsystem.

**Enumerate the algorithm allowlist as a hard-coded set**: Hard-coding the set
of PQC algorithms in Octavia would require a release to add new NIST-approved
algorithms.  A configurable ``ListOpt`` gives operators the flexibility to
adjust the allowlist as standards evolve and to accept algorithms that are
approved in their specific regulatory context.


Data model impact
-----------------

None.  All new behaviour is in-memory and config-driven.  No database schema
changes and no migrations are required.


REST API impact
---------------

No new API endpoints or request/response fields are introduced.

Existing endpoints change behaviour under ``pqc_strict_mode = True``:

* ``POST /v2/lbaas/listeners`` with ``default_tls_container_ref`` or
  ``client_ca_tls_container_ref`` referencing a non-compliant certificate:
  returns HTTP 400 with a fault message identifying the detected algorithm.

* ``POST /v2/lbaas/pools`` with backend TLS referencing a non-compliant
  certificate: returns HTTP 400.

* ``PUT`` equivalents of the above: same.

The behaviour change is controlled entirely by operator configuration.  It does
not affect the API contract for operators who leave ``pqc_strict_mode`` at its
default of ``False``.


Security impact
---------------

* ``_generate_private_key()`` and ``_generate_csr()`` are modified — these
  generate the certificates that secure the amphora mTLS control channel, the
  most security-sensitive internal communication path in Octavia.

* Certificate-load paths throughout the stack are touched to add algorithm
  inspection.

* The overall security posture improves: operators gain automated detection of
  quantum-vulnerable certificates and a path to enforce quantum-safe algorithm
  usage across the entire deployment.

* No new privilege escalation.  The ``pqc_allowed_algorithms`` list is
  operator-controlled configuration, not user input.

* The default values (``pqc_strict_mode = False``, ``key_algorithm = RSA-2048``)
  preserve current behaviour entirely, so no existing deployment is broken.


Notifications impact
--------------------

None.


Other end user impact
---------------------

End users (tenants) are not directly affected.  If an operator enables
``pqc_strict_mode = True`` before migrating all certificates, tenant attempts
to create or update TERMINATED_HTTPS listeners with existing RSA/ECDSA
certificates will receive HTTP 400 errors.  Operators must complete the
certificate migration before enabling strict mode (see Other deployer impact).


Performance Impact
------------------

The compliance check (algorithm type inspection on an already-loaded
pyca/cryptography object) is O(1) and adds negligible latency.  It runs at
configuration time — when a listener or pool is created or updated — not in the
data path.  There is no impact on request throughput or health-check frequency.


Other deployer impact
---------------------

**New configuration options** (all in ``[certificates]`` group):

.. csv-table:: New configuration options
   :header: Option,Type,Default,Description

   key_algorithm,StrOpt,RSA-2048,Algorithm used to generate amphora private keys
   pqc_strict_mode,BoolOpt,False,"If True reject non-compliant certs; if False warn"
   pqc_allowed_algorithms,ListOpt,"ML-DSA-44, ML-DSA-65, ML-DSA-87, ML-KEM-512, ML-KEM-768, ML-KEM-1024, SLH-DSA-SHAKE-128s, SLH-DSA-SHAKE-128f, SLH-DSA-SHAKE-256s",Algorithm names considered PQC-compliant

The default ``pqc_allowed_algorithms`` list corresponds to the NIST FIPS
203 (ML-KEM), FIPS 204 (ML-DSA), and FIPS 205 (SLH-DSA) standards.

**Recommended migration procedure for operators:**

1. Upgrade to this Octavia release.  ``pqc_strict_mode`` defaults to ``False``;
   existing deployments are unaffected.

2. Review WARNING log entries.  Each non-compliant certificate load emits a
   warning identifying the resource, the certificate subject, and the detected
   algorithm.  This gives operators a full inventory without disrupting service.

3. When pyca/cryptography ships ML-DSA support, set
   ``[certificates] key_algorithm = ML-DSA-65`` (or another level from the
   ML-DSA family as appropriate).  New amphora certificates will be generated
   with ML-DSA automatically.  Existing amphora certificates rotate within
   their normal ``cert_validity_time`` window (default: 30 days); no manual
   rotation is required.

4. Migrate listener, CA, and pool backend certificates stored in Barbican to
   PQC algorithms.  Operators issue new certificates signed with ML-DSA keys
   and update the relevant secret references.

5. Once all certificates are migrated, set
   ``[certificates] pqc_strict_mode = True``.  From this point, any attempt to
   configure a non-compliant certificate is rejected at the API layer.

.. warning::

   Enabling ``pqc_strict_mode = True`` before completing step 4 will cause
   HTTP 400 errors for any resource still referencing a classical-algorithm
   certificate.  Do not enable strict mode until the inventory from step 2 is
   fully remediated.


Developer impact
----------------

Developers adding new certificate-load paths to Octavia must call
``octavia.common.tls_utils.pqc_utils.check_algorithm_compliance()`` and handle
both the warning path and the strict-mode rejection path.  This requirement
will be documented in the developer guide.


Implementation
==============

Assignee(s)
-----------

Primary assignee:
  None

Other contributors:
  None

Work Items
----------

1. Add ``key_algorithm``, ``pqc_strict_mode``, and ``pqc_allowed_algorithms``
   config options to ``octavia/certificates/common/local.py`` and register them
   in ``octavia/common/config.py``.

2. Refactor ``_generate_private_key()`` in
   ``octavia/certificates/generator/local.py`` to read ``key_algorithm`` from
   config and dispatch to the appropriate pyca/cryptography primitive.  Remove
   the hardcoded ``rsa.generate_private_key()`` call.  Add startup validation
   that raises ``ConfigInvalidError`` for unsupported algorithm names.

3. Fix ``_generate_csr()`` in the same file to set ``KeyUsage`` extensions
   based on the key type (RSA vs EC vs PQC) rather than unconditionally setting
   ``key_encipherment = True``.

4. Implement ``octavia/common/tls_utils/pqc_utils.py`` containing
   ``check_algorithm_compliance()``.

5. Replace the ``.public_numbers()`` comparison in
   ``octavia/common/tls_utils/cert_parser.py`` with an algorithm-agnostic
   implementation using ``.public_bytes()`` serialisation.

6. Wire ``check_algorithm_compliance()`` at all four certificate-load points
   (``barbican.py``, ``cert_parser.py``, ``base.py``,
   ``generator/local.py``), applying the warn/reject behaviour based on
   ``pqc_strict_mode``.

7. Unit tests:

   * ``test_pqc_utils.py`` — compliance check with RSA, ECDSA, and mocked PQC
     key objects; verify correct algorithm name extraction and list membership
     logic.

   * ``test_local.py`` / ``test_local_csr.py`` — dispatch on ``key_algorithm``
     (RSA, ECDSA); startup failure for an unsupported algorithm string;
     correct ``KeyUsage`` per key type.

   * ``test_cert_parser.py`` — generic key comparison with RSA and EC keys.

8. Functional/Tempest tests:

   * Create a TERMINATED_HTTPS listener with an RSA certificate and
     ``pqc_strict_mode = False`` — listener creates successfully, WARNING is
     emitted.

   * Create a TERMINATED_HTTPS listener with an RSA certificate and
     ``pqc_strict_mode = True`` — API returns HTTP 400 with a fault message
     that identifies the algorithm.

   * Full ML-DSA path (listener with PQC cert, strict mode passes) is deferred
     until pyca/cryptography ships stable ML-DSA APIs.

9. Operator documentation: new section "Post-Quantum Cryptography Migration"
   covering config options, the migration procedure, and WARNING log format.

10. Configuration reference: document new options in the ``[certificates]``
    group.

11. Release note.


Dependencies
============

* **pyca/cryptography**: ML-DSA (FIPS 204) and ML-KEM (FIPS 203) are not yet
  exposed as stable public APIs in any released version of pyca/cryptography
  (v46 at time of writing).  Work items 1–8 can be fully implemented and tested
  today using RSA and ECDSA.  The ``ML-DSA-*`` and ``ML-KEM-*`` values in
  ``key_algorithm`` and ``pqc_allowed_algorithms`` become functional when the
  library ships them.  No minimum version requirement is introduced until that
  point.  Progress is tracked upstream in the pyca/cryptography issue tracker.

* **OpenSSL 3.5+**: PQC hybrid key exchange at the TLS transport layer
  (X25519MLKEM768) is provided by OpenSSL 3.5 and negotiates automatically
  for TLS 1.3 connections when the application does not restrict it.  Octavia
  does not restrict TLS 1.3 negotiation; this is therefore a platform-level
  dependency with no Octavia code change required.  Operators deploying amphora
  images on platforms with OpenSSL 3.5+ gain PQC key exchange automatically.

* Bug #2149791 — this spec addresses the ``octavia`` component findings from
  that report.

* OpenStack PQC Migration Pop-up Team wiki page:
  https://wiki.openstack.org/wiki/Post_quantum_openstack


Testing
=======

Unit test coverage is sufficient for the compliance-check utility and the
key-generation dispatch logic because both are pure functions operating on
in-memory pyca/cryptography objects with no external dependencies.

Tempest tests are needed for the two strict-mode API scenarios (warn path and
reject path) because they exercise the integration between the config layer, the
certificate-load pipeline, and the Octavia API response.  These scenarios use
standard RSA certificates, which are already available in the test environment.

The full ML-DSA end-to-end Tempest scenario (strict mode passes with a PQC
certificate) cannot be gated until pyca/cryptography exposes stable ML-DSA
APIs.  It will be added as a follow-up change once the dependency is satisfied.
Third-party CI or a separate experimental job may be used to validate PQC paths
on platforms where an unreleased library version is available.


Documentation Impact
====================

* **Operator guide**: New section "Post-Quantum Cryptography Migration"
  documenting the migration procedure, new configuration options, and the format
  of WARNING log messages emitted for non-compliant certificates.

* **Configuration reference**: New entries for ``key_algorithm``,
  ``pqc_strict_mode``, and ``pqc_allowed_algorithms`` in the ``[certificates]``
  group.

* **Developer guide**: New requirement to call
  ``check_algorithm_compliance()`` in any new certificate-load path, with
  guidance on handling the warn and reject outcomes.


References
==========

* Bug #2149791 — Octavia PQC vulnerabilities:
  https://bugs.launchpad.net/octavia/+bug/2149791

* OpenStack PQC Migration Pop-up Team wiki page (assessment guide, per-project
  inventory, guiding principles):
  https://wiki.openstack.org/wiki/Post_quantum_openstack

* NIST FIPS 203 — ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism):
  https://csrc.nist.gov/pubs/fips/203/final

* NIST FIPS 204 — ML-DSA (Module-Lattice-Based Digital Signature Algorithm):
  https://csrc.nist.gov/pubs/fips/204/final

* NIST FIPS 205 — SLH-DSA (Stateless Hash-Based Digital Signature Algorithm):
  https://csrc.nist.gov/pubs/fips/205/final

* NIST CSWP 39 — Considerations for Achieving Crypto Agility:
  https://www.nist.gov/publications/considerations-achieving-crypto-agility-strategies-and-practices

* IETF draft — Hybrid PQC Key Exchange in TLS 1.3:
  https://datatracker.ietf.org/doc/html/draft-ietf-tls-ecdhe-mlkem-04

* RFC 5280 — Internet X.509 Public Key Infrastructure Certificate and CRL
  Profile (KeyUsage extension):
  https://www.rfc-editor.org/rfc/rfc5280

* OpenStack PQC mailing list discussion:
  https://lists.openstack.org/archives/list/openstack-discuss@lists.openstack.org/thread/NH7SVJHLRA4ZLH4UINXULFX5SXKVDPZK/
