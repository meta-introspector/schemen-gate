# Contributing

Schemen Gate welcomes focused issues and pull requests. For substantial API,
authority, or threat-model changes, open an issue first so the intended boundary
can be reviewed before implementation.

## Development

Every tracked change, including documentation and research artifacts, must be
included in `RELEASE_MANIFEST.sha256` in the same commit. After completing the
edits, stage the intended additions and deletions using explicit paths, then run:

```bash
python scripts/release_manifest.py --write
git add RELEASE_MANIFEST.sha256
python scripts/release_manifest.py --verify
git diff --cached --check
```

The manifest enumerates Git-index paths and hashes their working-tree bytes.
New untracked files are excluded until staged. Stage the final versions of all
intended changes before committing; rerun the commands after any further edit.
Review the manifest diff along with the source diff. CI verifies the manifest;
it never regenerates or silently accepts changed hashes.

The `hygiene` CI job runs before the test, build, research, and release-contract
jobs. Repository administrators must require passing CI checks on `main` and
require pull requests so a failed push cannot become the public default branch.
Workflow files alone do not enforce GitHub branch rules.

```bash
python -m pip install -e ".[crypto,lockbox,onnx,rag,spiffe,torch,dev]"
python -m pytest -q
python -m ruff check src tests examples scripts research/cdp/experiments research/cdp/scripts research/cdp/examples
python -m ruff format --check src tests scripts examples
python scripts/validate_release_contract.py
python scripts/check_pypi_readme.py
python scripts/bootstrap_build_env.py
python scripts/build_release.py
python scripts/verify_dist.py
```

The complete release check requires `lake` from an elan/Lean installation.
`python scripts/release_check.py --skip-lean` is useful for a partial local
check, but it is not complete release evidence. Rebuilding the four checked-in
paper PDFs separately requires a TeX distribution plus `latexmk`; run
`make -C research/cdp paper`.

Pytest prepends this checkout's `src/` tree and propagates that path to child
Python processes, so a test run cannot silently use an editable installation
from a different Schemen Gate checkout.

The release bootstrap establishes pip from a fixed file URL, size, and SHA-256
before a package installer contacts an index, then accepts only the explicitly
enumerated hashes in `requirements/build.lock`. The subsequent build is offline
and uses only a Git-tracked export plus the generated commit-identity stamp.
The distribution verifier rejects any unexpected archive member and compares
every packaged Gate source file byte-for-byte with the reviewed commit.

Security-sensitive changes must include adversarial rejection tests. Changes to
authority, key derivation, canonicalization, signatures, replay handling, trust
anchors, or runtime contracts must document the exact old and new boundary.

Optional service development is documented under `services/`. Services have
independent packages, Python requirements, and CI; installing the core does not
install them. For the credential broker, run the commands in
[`services/credential-broker/README.md`](services/credential-broker/README.md).
Do not copy local environment files, credentials, review transcripts, or
generated test receipts into a public service directory. The root Apache-2.0
license applies to service source as well as library source.

Keep pull requests narrow, explain the user-visible behavior, and add or update
tests and documentation together. Contributions outside `research/cdp/` are
provided under the root Apache-2.0 license as described in section 5 of that
license. Contributions inside `research/cdp/` use the path-specific license in
[`research/cdp/LICENSES.md`](research/cdp/LICENSES.md). No separate contributor
license agreement is currently required.

Do not commit credentials, generated `build/` or `dist/` trees, `.egg-info`,
model weights, caches, or production receipts.

## Native acceptance and process exit

Run acceptance from a clean, isolated virtual environment created without
`--system-site-packages`. The native and release entry points reject external
import roots before importing native ML code. The declared checkout, its `src`
and `scripts` directories, the venv, and the interpreter standard library are
allowed. This detects mixed Python installations, not every dynamically linked
native library or an adversarial Python interpreter.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[crypto,lockbox,onnx,rag,spiffe,torch,dev]' cmake
python scripts/check_native.py
python scripts/release_check.py
```

These commands run under a parent that does not import ML libraries and waits
for the child process to exit. A printed test PASS followed by a crash is a
failed acceptance. Each invocation prints the path to a private receipt and
stdout/stderr logs. Receipts record exit/signal status and stable log hashes;
NaN/infinite timeouts are rejected. They are diagnostic records, not signed
execution attestations. No retries occur automatically.

On POSIX, the observer creates an owned process group and stops remaining group
members on timeout or interruption. A successful child that leaves descendants
is rejected. If cleanup cannot be confirmed, logs are not declared stable by
hashing them. This does not contain descendants that deliberately detach into
new sessions; a killed observer can leave a RUNNING receipt. Other platforms
only supervise the immediate child. Direct pytest and other scripts remain
outside these entry points unless run through `scripts/native_acceptance.py`.

Raw logs can contain sensitive data. `--acceptance-logs` explicitly opts in to
printing them after the run; hosted CI uses that flag for its synthetic test
fixtures. Local logs are not uploaded automatically. Example direct supervision:

```bash
python scripts/native_acceptance.py --receipt-dir /tmp/gate-check-unique \
  --cwd "$PWD" --timeout 600 -- python -m pytest -q tests/test_torch_gate.py
```

Use a new receipt directory for each run. The isolated environment prevents the
observed mixed-installation condition; this does not claim that an upstream
PyTorch shutdown defect has been repaired.
