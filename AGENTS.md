# Repository Guidelines

- Code: `check_pro_security_status.py` (CLI in `main()`, logic in `CheckProSecurityStatus`). Tests: `tests/test_check_pro_security_status.py`, sample client output in `tests/output/`. Python >=3.12, no runtime dependencies.
- Setup: `uv sync --locked --all-extras --dev`
- Lint: `uv run ruff check`
- Test (as in CI): `uv run pytest --cov=check_pro_security_status`
- Style: standard Python, type annotations kept, tests named `test_<behavior>`.
- Tests mock `subprocess.run` and `nagios_exit` exits; they stay offline and deterministic.
- Every package update `status` and `reboot_required` value of `pro security-status --format json` needs a test. Unrecognized output must be UNKNOWN, never OK.
- Commits: short, imperative summaries.
