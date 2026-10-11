# Contributing to SAFIX

Thanks for your interest in improving SAFIX. Please read this before opening a pull request —
it explains how contributions are licensed, which matters because SAFIX is **dual-licensed**.

## The dual-license model (why we ask for a CLA)

SAFIX is released to the public under the **GNU AGPL-3.0-or-later** (see [`LICENSE`](LICENSE)).
The copyright holder also offers SAFIX under a **separate commercial license** to organizations
that cannot accept the AGPL's terms.

To be able to offer that commercial license, the project must hold the rights to **all** the code
in it — including your contributions. That is what the Contributor License Agreement (CLA) in
[`CLA.md`](CLA.md) provides: you keep the copyright to your work, but you grant the copyright
holder the right to license your contribution under both the AGPL **and** other terms (including
commercial ones). Your contribution to the public repository is, and remains, available under the
AGPL like the rest of SAFIX.

> This CLA is a lightweight template. If you are contributing on behalf of an employer, or have
> any doubt about your rights to contribute, please have it reviewed before signing.

## How to agree to the CLA

Both of the following are required on every contribution:

1. **Developer Certificate of Origin (DCO) sign-off.** Add a `Signed-off-by` line to each commit
   (certifying you wrote the code or have the right to submit it — the DCO text is in
   [`CLA.md`](CLA.md)). Git does this for you:

   ```bash
   git commit -s -m "Your message"
   ```

2. **CLA acceptance.** The first time you open a pull request, add a comment stating:

   > I have read and agree to the Contributor License Agreement in CLA.md.

   (and include your name and the email you commit with). One acceptance covers your future
   contributions unless the CLA changes.

## Development setup

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate   Linux/macOS: source .venv/bin/activate
pip install -e ".[web,dev]"
pytest -q                 # all tests must pass
```

## What a good PR looks like

- **Tests pass** (`pytest -q`) and new behavior is covered by tests. Detector changes should keep
  the detection-rate / false-positive gates in `tests/integration/test_detection_rate.py` green.
- **No new false positives** on the benign corpus; new detectors carry a severity, a confidence,
  and a `benign` note (see [`docs/RULES.md`](docs/RULES.md)).
- Code matches the surrounding style; detectors map findings to their source attack-vector IDs.
- The change is focused and the PR description says what and why.

## Reporting security issues

Please do **not** open a public issue for a security vulnerability in SAFIX itself. Email
boringllm58@gmail.com instead.
