# AGENTS.md — Octavia

OpenStack Load Balancer as a Service (LBaaS). Python project using `pbr` build backend, `tox`/`stestr` for testing, Alembic for DB migrations, TaskFlow for orchestration.

## Contribution workflow (non-obvious)

- Reviews go through **Gerrit** at `opendev.org`, NOT GitHub. PRs opened on GitHub are ignored.
- Bugs go to **Launchpad** (`launchpad.net/octavia`), not GitHub Issues.

## Commands

### Tests

```bash
tox -e py3                          # unit tests
tox -e functional-py3               # functional tests (no real cloud needed)
tox -e cover                        # coverage report (must be ≥ 92%)
```

Run a focused subset by passing a dotted module path or regex as posarg:

```bash
tox -e py3 -- octavia.tests.unit.common.test_utils
tox -e functional-py3 -- api.v2
tox -e py3 -- --failing             # re-run only previously failing tests
```

Runner is **stestr** (not pytest). `OS_TEST_PATH` selects unit vs functional.

### Lint / style

```bash
tox -e pep8                         # full lint gate (see order below)
```

`pep8` runs in this order:
1. `flake8`
2. `doc8` (RST, max 79 chars)
3. `bandit -r octavia -ll -ii -x tests`
4. `python -m unittest specs-tests.test_titles` (validates spec RST structure)
5. `./tools/misc-sanity-checks.sh` (validates `.pot`/`.po` translation files)
6. `./tools/coding-checks.sh --pylint` (pylint, parallel `-j 0`)
7. `./tools/check_unit_test_structure.sh` (mirrors check — see below)
8. `bashate` on all `*.sh`

Run pylint alone on changed files only:
```bash
./tools/coding-checks.sh --pylint HEAD~1
```

### Config / policy generation

```bash
tox -e genconfig     # → etc/octavia/octavia.conf.sample
tox -e genpolicy     # → etc/octavia/policy.yaml.sample
```

### DB migrations (Alembic via `octavia-db-manage`)

```bash
octavia-db-manage upgrade head
octavia-db-manage revision -m "description"   # new migration
octavia-db-manage check_migration             # validate branch state
```

**Downgrade is hard-disabled** — the CLI raises `SystemExit` if attempted.

## Unit test structure — strict mirroring

Every file `octavia/tests/unit/foo/bar/test_baz.py` **must** have a counterpart at `octavia/foo/bar/baz.py`. This is enforced by `tools/check_unit_test_structure.sh` (part of `pep8`). The only exceptions (hardcoded in that script):

- `amphorae/drivers/haproxy/test_rest_api_driver_0_5.py`
- `amphorae/drivers/haproxy/test_rest_api_driver_1_0.py`
- `controller/worker/v2/tasks/test_database_tasks_quota.py`

To add a new exception, edit `tools/check_unit_test_structure.sh`.

## Hacking rules (enforced by flake8 extensions)

| Rule | What it bans / requires |
|------|------------------------|
| O321 | Use `oslo_serialization.jsonutils`, not stdlib `json` |
| O322 | No `@author` tags |
| O323 | `assertTrue`/`assertFalse` instead of `assertEqual(True/False, x)` |
| O324 | No mutable default arguments |
| O339 | `LOG.warning()` not `LOG.warn()` |
| O341 | No translation wrappers on log messages (`_()`) |
| O342 | Exception messages should be translated |
| O345 | **`eventlet` is banned** (hard architectural constraint) |
| O346 | No backslash line continuation — use parentheses |
| O347 | TaskFlow revert methods must accept `**kwargs` |
| O348 | Use `oslo_log.log`, not stdlib `logging` |

## Code layout

```
octavia/
  api/v2/            # Pecan REST API (controllers + WSME types)
  amphorae/          # Amphora subsystem: agent running inside the VM, drivers controlling it
  cmd/               # Entry-point scripts (octavia-api, amphora-agent, etc.)
  common/            # constants.py, data_models.py, exceptions.py, config.py, jinja/ templates
  controller/worker/ # TaskFlow orchestration: flows/ + tasks/
  db/                # SQLAlchemy models, repositories.py, Alembic migrations
  network/           # Neutron driver (allowed_address_pairs)
  certificates/      # TLS cert managers (local, Barbican, Castellan)
  hacking/checks.py  # Custom flake8 checks
  tests/unit/        # Must mirror source tree exactly
  tests/functional/  # Mocked API — no real cloud required
```

Key internal data path: API controller → `octavia.api.drivers` provider interface → `octavia-worker` via oslo.messaging → TaskFlow flows/tasks → compute/network/amphora drivers.

## Other conventions

- Line length: **79 characters** (flake8, pylint, doc8 all enforce this).
- `DeprecationWarning` is always shown in tests (`PYTHONWARNINGS=always::DeprecationWarning`).
- `pyupgrade --py38-plus` runs via pre-commit hooks. Install with `pre-commit install`.
- All APIs (including internal ones between components) must be versioned.
- Design is idempotency-first — repeated messages must not break state.
- Specs (design docs) live in `specs/` as `.rst` files and must pass `specs-tests/test_titles.py` which validates exactly 7 required top-level sections.
- Diskimage-builder amphora image tooling lives in `diskimage-create/` with its own `tox.ini`.
