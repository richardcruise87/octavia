..
 This work is licensed under a Creative Commons Attribution 3.0 Unported
 License.

 http://creativecommons.org/licenses/by/3.0/legalcode

=======================================
Post-Quantum Cryptography Check Mode
=======================================

https://bugs.launchpad.net/octavia/+bug/2149791

Octavia's internal certificate infrastructure and TLS configuration paths
currently use classical asymmetric algorithms (RSA, ECDSA) that are vulnerable
to quantum attack via Shor's algorithm.  This spec introduces algorithm-agnostic
key generation and configurable per-plane PQC check modes, giving operators the
tools to audit and enforce quantum-safe algorithm usage on the control plane,
the data plane, or both — at whatever pace their deployment requires — without
breaking existing deployments.


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

Without configurable check modes and an operator-defined algorithm allowlist,
operators cannot enforce quantum-safe algorithm requirements or signal
programmatically that their deployment has completed the migration.  The lack
of enforcement makes compliance audits manual and error-prone.

Use cases:

* A deployer has completed the quantum migration of their control plane (amphora
  mTLS certificates) but still has legacy RSA certificates on listener TLS
  endpoints.  They want to enforce PQC compliance on the control plane while
  keeping the data plane check silent to avoid log noise during the ongoing
  listener migration.

* A deployer wants to begin auditing their deployment for quantum-vulnerable
  certificates without disrupting service.  They enable warning mode on one
  or both planes and review the resulting log inventory before committing to
  migration.

* A deployer wants new amphora certificates to use ML-DSA once their platform's
  pyca/cryptography library supports it, without redeploying Octavia.

* A security auditor wants to verify that no TERMINATED_HTTPS listener in the
  deployment accepts traffic using a quantum-vulnerable certificate, receiving
  an API error (not just a log warning) if one is submitted.


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

.. note::

   ``key_algorithm`` currently governs only **internally generated amphora
   mTLS certificates**.  All other certificate material — listener TLS
   certificates, client-auth CA certificates, pool backend TLS certificates,
   and the operator CA key pair (``ca_certificate`` / ``ca_private_key``) —
   is user-supplied via Barbican or provided by the operator externally.
   ``key_algorithm`` has no effect on those keys today.  Any future
   Octavia-generated certificate path should also honour ``key_algorithm``
   as the single source of truth for all internally generated key material.

The ``_generate_csr()`` function in the same file sets
``KeyUsage.key_encipherment = True`` unconditionally.  This is correct for RSA
(key transport) but violates RFC 5280 for ECDSA and ML-DSA keys, which require
only ``digital_signature`` (and ``key_agreement`` for ECDH-capable keys).  This
RFC 5280 compliance defect is corrected as part of this work item: ``KeyUsage``
is set based on the key type returned by the library.

**Part 2 — PQC compliance checker utility**

A new module ``octavia/common/tls_utils/pqc_utils.py`` exposes a single
public function::

    check_algorithm_compliance(public_key_or_cert, plane) -> (algorithm_name, is_compliant)

The ``plane`` parameter accepts ``'control'`` or ``'data'``, allowing the
function to read the appropriate per-plane check-mode config option and apply
it consistently.  The function:

* accepts a pyca/cryptography public key or X.509 certificate object;
* extracts the public key algorithm using the library's own introspection
  APIs (``isinstance`` checks against library key classes, OID comparison
  for PQC key types);
* returns the detected algorithm name and whether it appears in the
  operator-configured ``pqc_allowed_algorithms`` list.

The function contains no custom OID tables or cryptographic logic — all
algorithm knowledge comes from pyca/cryptography.

The existing ``cert_parser.py`` public key comparison uses ``.public_numbers()``,
which is not available on ML-DSA and ML-KEM key objects.  This call is replaced
with an algorithm-agnostic comparison using ``.public_bytes()`` serialisation,
which works across all key types.

**Part 3 — Per-plane PQC check modes**

Two new config options are added to the ``[certificates]`` group, one for each
plane:

.. csv-table::
   :header: Option, Values, Default

   pqc_control_plane_check_mode,"DISABLED, PERMISSIVE, STRICT",DISABLED
   pqc_data_plane_check_mode,"DISABLED, PERMISSIVE, STRICT",DISABLED

The three mode values have the following semantics:

* **DISABLED**: no compliance check is performed, and no log entry is emitted.
  Suitable for deployments that have explicitly accepted the risk, use an
  external compliance tool, or are mid-migration on that plane.

* **PERMISSIVE**: the compliance check runs; when a non-compliant algorithm is
  detected, ``LOG.warning`` is emitted with the certificate subject, detected
  algorithm name, and a reference to the operator migration guide.  Processing
  continues normally.

* **STRICT**: the compliance check runs; when a non-compliant algorithm is
  detected, ``exceptions.CertificateValidationException`` is raised.  API
  callers receive HTTP 400 with a fault message identifying the algorithm.  The
  service refuses to configure the resource until the certificate is replaced
  with a compliant one.

Both options default to ``DISABLED``.  This faithfully preserves existing
behaviour (no checking at all) and requires operators to explicitly opt in to
any level of compliance checking.

The control plane covers amphora mTLS certificates generated by Octavia
itself.  The data plane covers all user-provided certificates: listener TLS
certificates, client-auth CA certificates, and pool backend TLS certificates.

.. csv-table:: Certificate load points and plane assignment
   :header: Load point, File, Trigger, Plane

   Amphora mTLS cert generation,octavia/certificates/generator/local.py,generate_cert_key_pair(),control
   Listener TLS cert (Barbican),octavia/certificates/manager/barbican.py,get_cert(),data
   Client-auth CA cert,octavia/api/v2/controllers/base.py,CA cert load,data
   Pool backend TLS cert,octavia/common/tls_utils/cert_parser.py,cert parse,data

**Interaction between ``key_algorithm`` and ``pqc_control_plane_check_mode``**:
If ``key_algorithm`` names an algorithm that is not in ``pqc_allowed_algorithms``
and ``pqc_control_plane_check_mode = STRICT``, Octavia would generate a
non-compliant amphora certificate and then immediately reject it, breaking
amphora provisioning.  To surface this misconfiguration early, Octavia performs
a startup check: if ``pqc_control_plane_check_mode = STRICT``, ``key_algorithm``
is validated against ``pqc_allowed_algorithms`` at boot, and
``ConfigInvalidError`` is raised if it is not compliant.


Alternatives
------------

**3-value enum on a single global option** (i.e. one ``pqc_check_mode`` option
covering all certificate load points): simpler surface area, but cannot model
the common case where the control plane is fully migrated (STRICT) while
data-plane listener certificates are still in flux (DISABLED or PERMISSIVE).
Rejected because it prevents independent migration of the two planes.

**Global mode with optional per-plane overrides** (a ``pqc_check_mode`` global
plus ``pqc_control_plane_check_mode`` and ``pqc_data_plane_check_mode``
overrides): adds a third option and introduces "unset vs. default value"
ambiguity that oslo.config does not have a native mechanism to express cleanly.
The two-option approach in this spec achieves the same result without the
resolution complexity.

**Boolean ``pqc_checks_enabled`` + boolean ``pqc_strict_mode``**: two booleans
to express a three-state behaviour creates a fourth state
(``enabled=False, strict=True``) that is contradictory and requires special
documentation.  A single 3-value enum per plane is semantically unambiguous.

**Single mode with separate per-plane algorithm allowlists**: useful for
applying different algorithm subsets to each plane, but does not solve the use
case of enforcing STRICT on one plane and completely silencing the other.
May be considered as a future extension.

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

Existing endpoints change behaviour when ``pqc_data_plane_check_mode = STRICT``:

* ``POST /v2/lbaas/listeners`` with ``default_tls_container_ref`` or
  ``client_ca_tls_container_ref`` referencing a non-compliant certificate:
  returns HTTP 400 with a fault message identifying the detected algorithm.

* ``POST /v2/lbaas/pools`` with backend TLS referencing a non-compliant
  certificate: returns HTTP 400.

* ``PUT`` equivalents of the above: same.

When ``pqc_data_plane_check_mode = PERMISSIVE``, the same operations succeed
but emit a WARNING log entry.  When ``DISABLED`` (the default), no behavioural
change occurs.

The behaviour change is controlled entirely by operator configuration.  It does
not affect the API contract for operators who leave both check modes at their
defaults of ``DISABLED``.


Security impact
---------------

* ``_generate_private_key()`` and ``_generate_csr()`` are modified — these
  generate the certificates that secure the amphora mTLS control channel, the
  most security-sensitive internal communication path in Octavia.

* Certificate-load paths throughout the stack are touched to add algorithm
  inspection.

* The overall security posture improves: operators gain automated detection of
  quantum-vulnerable certificates and a path to enforce quantum-safe algorithm
  usage independently on the control plane and data plane.

* No new privilege escalation.  The ``pqc_allowed_algorithms`` list is
  operator-controlled configuration, not user input.

* The default values (``DISABLED`` for both planes, ``key_algorithm = RSA-2048``)
  preserve current behaviour entirely, so no existing deployment is broken.


Notifications impact
--------------------

None.


Other end user impact
---------------------

End users (tenants) are not directly affected when check modes are ``DISABLED``
or ``PERMISSIVE``.  If an operator enables ``pqc_data_plane_check_mode = STRICT``
before migrating all data-plane certificates, tenant attempts to create or
update TERMINATED_HTTPS listeners or pools with existing RSA/ECDSA certificates
will receive HTTP 400 errors.  Operators must complete the data-plane
certificate migration before enabling strict mode on the data plane.


Performance Impact
------------------

The compliance check (algorithm type inspection on an already-loaded
pyca/cryptography object) is O(1) and adds negligible latency.  It runs at
configuration time — when a listener or pool is created or updated — not in the
data path.  There is no impact on request throughput or health-check frequency.
When both check modes are ``DISABLED`` (the default), there is no overhead at
all.


Other deployer impact
---------------------

**New configuration options** (all in ``[certificates]`` group):

.. csv-table:: New configuration options
   :header: Option,Type,Default,Description

   key_algorithm,StrOpt,RSA-2048,"Algorithm for amphora private key generation (amphora mTLS only — see note in Proposed change)"
   pqc_control_plane_check_mode,StrOpt,DISABLED,"DISABLED / PERMISSIVE / STRICT for amphora mTLS certificates"
   pqc_data_plane_check_mode,StrOpt,DISABLED,"DISABLED / PERMISSIVE / STRICT for listener TLS / CA / pool backend certificates"
   pqc_allowed_algorithms,ListOpt,"ML-DSA-44, ML-DSA-65, ML-DSA-87, ML-KEM-512, ML-KEM-768, ML-KEM-1024, SLH-DSA-SHAKE-128s, SLH-DSA-SHAKE-128f, SLH-DSA-SHAKE-256s",Algorithm names considered PQC-compliant (shared across both planes)

The default ``pqc_allowed_algorithms`` list corresponds to the NIST FIPS
203 (ML-KEM), FIPS 204 (ML-DSA), and FIPS 205 (SLH-DSA) standards.

**Recommended migration procedure for operators:**

1. Upgrade to this Octavia release.  Both check modes default to ``DISABLED``;
   existing deployments are entirely unaffected.

2. **Audit phase** — enable PERMISSIVE on the plane(s) of interest to surface
   non-compliant certificates via WARNING logs.  Both planes can be audited
   simultaneously or one at a time:

   .. code-block:: ini

      [certificates]
      pqc_control_plane_check_mode = PERMISSIVE
      pqc_data_plane_check_mode    = PERMISSIVE

   Review the log output to build an inventory of non-compliant resources.
   Silence a fully-migrated plane by returning it to ``DISABLED`` while the
   other remains in ``PERMISSIVE``.

3. **Control-plane migration** — when pyca/cryptography ships ML-DSA support,
   set ``key_algorithm`` to the desired PQC algorithm.  New amphora
   certificates will use ML-DSA automatically; existing ones rotate within
   their ``cert_validity_time`` window (default: 30 days) with no manual
   intervention.  Once the control-plane inventory is clean, advance to
   ``STRICT``:

   .. code-block:: ini

      [certificates]
      key_algorithm                = ML-DSA-65
      pqc_control_plane_check_mode = STRICT

4. **Data-plane migration** — migrate listener, CA, and pool backend
   certificates stored in Barbican to PQC algorithms.  Once the data-plane
   inventory from step 2 is fully remediated, advance to ``STRICT``:

   .. code-block:: ini

      [certificates]
      pqc_data_plane_check_mode = STRICT

.. warning::

   Before advancing either plane to ``STRICT``, verify that all certificates
   on that plane have been migrated.  Enabling ``STRICT`` on the data plane
   before step 4 is complete will cause HTTP 400 errors for any listener or
   pool still referencing a classical-algorithm certificate.  Enabling
   ``STRICT`` on the control plane before ``key_algorithm`` is set to a
   compliant algorithm will cause a ``ConfigInvalidError`` at service startup.


Developer impact
----------------

Developers adding new certificate-load paths to Octavia must call
``octavia.common.tls_utils.pqc_utils.check_algorithm_compliance(cert_or_key,
plane)`` and pass the appropriate plane identifier (``'control'`` or
``'data'``).  The function handles mode evaluation internally so callers do
not need to inspect check-mode config options directly.  This requirement
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

1. Add ``key_algorithm``, ``pqc_control_plane_check_mode``,
   ``pqc_data_plane_check_mode``, and ``pqc_allowed_algorithms`` config options
   to ``octavia/certificates/common/local.py`` and register them in
   ``octavia/common/config.py``.

2. Refactor ``_generate_private_key()`` in
   ``octavia/certificates/generator/local.py`` to read ``key_algorithm`` from
   config and dispatch to the appropriate pyca/cryptography primitive.  Remove
   the hardcoded ``rsa.generate_private_key()`` call.  Add startup validation
   that raises ``ConfigInvalidError`` for unsupported algorithm names.

3. Add startup validation: if ``pqc_control_plane_check_mode = STRICT``,
   verify that ``key_algorithm`` is in ``pqc_allowed_algorithms``, raising
   ``ConfigInvalidError`` if not.

4. Fix ``_generate_csr()`` in the same file to set ``KeyUsage`` extensions
   based on the key type (RSA vs EC vs PQC) rather than unconditionally setting
   ``key_encipherment = True``.

5. Implement ``octavia/common/tls_utils/pqc_utils.py`` containing
   ``check_algorithm_compliance(cert_or_key, plane)``.

6. Replace the ``.public_numbers()`` comparison in
   ``octavia/common/tls_utils/cert_parser.py`` with an algorithm-agnostic
   implementation using ``.public_bytes()`` serialisation.

7. Wire ``check_algorithm_compliance()`` at all four certificate-load points
   (``barbican.py``, ``cert_parser.py``, ``base.py``,
   ``generator/local.py``), passing the appropriate plane identifier.

8. Unit tests:

   * ``test_pqc_utils.py`` — compliance check with RSA, ECDSA, and mocked PQC
     key objects; all three mode values (DISABLED, PERMISSIVE, STRICT) for each
     plane; verify no log entry when DISABLED, WARNING when PERMISSIVE, and
     exception when STRICT.

   * ``test_local.py`` / ``test_local_csr.py`` — dispatch on ``key_algorithm``
     (RSA, ECDSA); startup failure for an unsupported algorithm string;
     startup failure when control plane is STRICT and ``key_algorithm`` is
     non-compliant; correct ``KeyUsage`` per key type.

   * ``test_cert_parser.py`` — generic key comparison with RSA and EC keys.

9. Functional/Tempest tests:

   * Create a TERMINATED_HTTPS listener with an RSA certificate and
     ``pqc_data_plane_check_mode = DISABLED`` — listener creates successfully,
     no WARNING logged.

   * Create a TERMINATED_HTTPS listener with an RSA certificate and
     ``pqc_data_plane_check_mode = PERMISSIVE`` — listener creates
     successfully, WARNING is emitted.

   * Create a TERMINATED_HTTPS listener with an RSA certificate and
     ``pqc_data_plane_check_mode = STRICT`` — API returns HTTP 400 with a
     fault message that identifies the algorithm.

   * Full ML-DSA path (listener with PQC cert, STRICT mode passes) is deferred
     until pyca/cryptography ships stable ML-DSA APIs.

10. Operator documentation: new section "Post-Quantum Cryptography Migration"
    covering config options, per-plane migration procedure, and WARNING log
    format.

11. Configuration reference: document new options in the ``[certificates]``
    group, including the scope note for ``key_algorithm``.

12. Release note.


Dependencies
============

* **pyca/cryptography**: ML-DSA (FIPS 204) and ML-KEM (FIPS 203) are not yet
  exposed as stable public APIs in any released version of pyca/cryptography
  (v46 at time of writing).  Work items 1–9 can be fully implemented and tested
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
in-memory pyca/cryptography objects with no external dependencies.  All three
mode values (DISABLED, PERMISSIVE, STRICT) must be exercised for both planes
in unit tests.

Tempest tests are needed for the three data-plane check-mode scenarios
(DISABLED, PERMISSIVE, STRICT) because they exercise the integration between
the config layer, the certificate-load pipeline, and the Octavia API response.
These scenarios use standard RSA certificates, which are already available in
the test environment.

The full ML-DSA end-to-end Tempest scenario (STRICT mode passes with a PQC
certificate) cannot be gated until pyca/cryptography exposes stable ML-DSA
APIs.  It will be added as a follow-up change once the dependency is satisfied.
Third-party CI or a separate experimental job may be used to validate PQC paths
on platforms where an unreleased library version is available.


Documentation Impact
====================

* **Operator guide**: New section "Post-Quantum Cryptography Migration"
  documenting the per-plane migration procedure, new configuration options, and
  the format of WARNING log messages emitted for non-compliant certificates.

* **Configuration reference**: New entries for ``key_algorithm``,
  ``pqc_control_plane_check_mode``, ``pqc_data_plane_check_mode``, and
  ``pqc_allowed_algorithms`` in the ``[certificates]`` group.  The reference
  entry for ``key_algorithm`` must note explicitly that it currently governs
  only internally generated amphora certificates, not operator-provided or
  Barbican-stored keys.

* **Developer guide**: New requirement to call
  ``check_algorithm_compliance(cert_or_key, plane)`` in any new
  certificate-load path, with guidance on the correct plane identifier and
  how to handle the PERMISSIVE and STRICT outcomes.


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
