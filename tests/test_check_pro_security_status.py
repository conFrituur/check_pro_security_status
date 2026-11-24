import json
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from check_pro_security_status import (
    CheckProSecurityStatus,
    SecurityStatusError,
    main,
)

OUTPUT = Path(__file__).parent / "output"
ESM = ["esm-apps", "esm-infra"]


def status_output(
    attached: bool = True,
    enabled: list[str] | None = None,
    entitled: list[str] | None = None,
    reboot_required: str = "no",
    packages: list[tuple[str, str]] = (),
    fixed_cves: int = 0,
) -> str:
    return json.dumps(
        {
            "_schema_version": "0.1",
            "livepatch": {
                "fixed_cves": [
                    {"name": f"cve-2013-{i}", "patched": True} for i in range(fixed_cves)
                ]
            },
            "packages": [
                {
                    "download_size": 1000,
                    "origin": "security.ubuntu.com",
                    "package": name,
                    "service_name": "standard-security",
                    "status": status,
                    "version": "1.0",
                }
                for name, status in packages
            ],
            "summary": {
                "reboot_required": reboot_required,
                "ua": {
                    "attached": attached,
                    "enabled_services": ESM if enabled is None else enabled,
                    "entitled_services": ESM if entitled is None else entitled,
                },
            },
        }
    )


def run_check(check: CheckProSecurityStatus, output: str, capsys):
    check.run_status = lambda: output
    with pytest.raises(SystemExit) as exit_info:
        check.check_status()
    return exit_info.value.code, capsys.readouterr().out.strip()


def completed(stdout: str = "", stderr: str = "", returncode: int = 0):
    return subprocess.CompletedProcess([], returncode, stdout, stderr)


def test_main_constructs_and_runs_checker() -> None:
    args = ["check_pro_security_status.py", "-w", "3", "-c", "7", "--verbose", "--list-livepatch-cves"]
    with (
        patch("sys.argv", args),
        patch("check_pro_security_status.CheckProSecurityStatus") as cls,
    ):
        main()
    cls.assert_called_once_with(3, 7, True, True)
    cls.return_value.check_status.assert_called_once_with()


def test_main_short_list_option() -> None:
    with (
        patch("sys.argv", ["check_pro_security_status.py", "-l"]),
        patch("check_pro_security_status.CheckProSecurityStatus") as cls,
    ):
        cls.DEFAULT_WARNING_UPDATES = 1
        cls.DEFAULT_CRITICAL_UPDATES = 10
        main()
    cls.assert_called_once_with(1, 10, False, True)


def test_main_defaults() -> None:
    with (
        patch("sys.argv", ["check_pro_security_status.py"]),
        patch("check_pro_security_status.CheckProSecurityStatus") as cls,
    ):
        cls.DEFAULT_WARNING_UPDATES = 1
        cls.DEFAULT_CRITICAL_UPDATES = 10
        main()
    cls.assert_called_once_with(1, 10, False, False)


def test_main_rejects_invalid_thresholds() -> None:
    args = ["check_pro_security_status.py", "-w", "10", "-c", "5"]
    with patch("sys.argv", args), pytest.raises(SystemExit) as exit_info:
        main()
    assert exit_info.value.code == 2


@pytest.mark.parametrize(
    "kwargs",
    [
        {"warning_updates": 0},
        {"critical_updates": -1},
        {"warning_updates": 5, "critical_updates": 4},
    ],
)
def test_invalid_thresholds(kwargs) -> None:
    with pytest.raises(ValueError):
        CheckProSecurityStatus(**kwargs)


def test_equal_thresholds_are_allowed() -> None:
    CheckProSecurityStatus(warning_updates=1, critical_updates=1)


def test_sample_attached_output_is_ok(capsys) -> None:
    code, out = run_check(
        CheckProSecurityStatus(), (OUTPUT / "attached_ok.json").read_text(), capsys
    )
    assert code == 0
    assert out == (
        "OK - attached to Ubuntu Pro (esm-infra, esm-apps enabled); "
        "no security updates available; "
        "reboot required, the running kernel is covered by Livepatch; "
        "1 CVEs fixed by Livepatch"
        " | security_updates=0;1;10;0 blocked_security_updates=0;;;0"
        " livepatch_fixed_cves=1;;;0"
    )


def test_sample_unattached_output_is_critical(capsys) -> None:
    code, out = run_check(
        CheckProSecurityStatus(), (OUTPUT / "unattached.json").read_text(), capsys
    )
    assert code == 2
    assert out == (
        "CRITICAL - machine is not attached to an Ubuntu Pro subscription; "
        "0 CVEs fixed by Livepatch"
        " | security_updates=1;1;10;0 blocked_security_updates=1;;;0"
        " livepatch_fixed_cves=0;;;0"
    )


# --- attachment -------------------------------------------------------------


@pytest.mark.parametrize(
    ("attached", "enabled", "entitled", "code", "message"),
    [
        (True, ESM, ESM, 0, "attached to Ubuntu Pro (esm-infra, esm-apps enabled)"),
        (True, ["esm-infra"], ["esm-infra"], 0, "(esm-infra enabled)"),
        (True, [], [], 0, "(no ESM enabled)"),
        (True, ["esm-infra"], ESM, 1, "esm-apps entitled but not enabled"),
        (True, [], ESM, 1, "esm-infra, esm-apps entitled but not enabled"),
        (False, [], [], 2, "machine is not attached to an Ubuntu Pro subscription"),
    ],
)
def test_attachment(attached, enabled, entitled, code, message, capsys) -> None:
    output = status_output(attached=attached, enabled=enabled, entitled=entitled)
    result, out = run_check(CheckProSecurityStatus(), output, capsys)
    assert result == code
    assert message in out


# --- updates ----------------------------------------------------------------


@pytest.mark.parametrize("status", ["upgrade_available", "upgrade_available_not_preferred"])
def test_installable_update_statuses_warn(status, capsys) -> None:
    output = status_output(packages=[("openssl", status)])
    code, out = run_check(CheckProSecurityStatus(), output, capsys)
    assert code == 1
    assert out.startswith("WARNING - 1 security updates available: openssl;")


@pytest.mark.parametrize(
    ("status", "message"),
    [
        ("pending_attach", "1 security updates need an attached Ubuntu Pro subscription"),
        ("pending_enable", "1 security updates need an entitled ESM service to be enabled"),
        ("upgrade_unavailable", "1 security updates are not covered by the subscription"),
    ],
)
def test_blocked_update_statuses_warn(status, message, capsys) -> None:
    output = status_output(packages=[("ansible", status)])
    code, out = run_check(CheckProSecurityStatus(), output, capsys)
    assert code == 1
    assert out.startswith(f"WARNING - {message}: ansible;")
    assert "blocked_security_updates=1" in out


def test_livepatch_fixed_cves_are_reported_but_not_alerted(capsys) -> None:
    code, out = run_check(
        CheckProSecurityStatus(), status_output(fixed_cves=3), capsys
    )
    assert code == 0
    assert "3 CVEs fixed by Livepatch" in out
    assert "livepatch_fixed_cves=3;;;0" in out


def test_livepatch_cves_are_listed_on_separate_lines_when_requested(capsys) -> None:
    check = CheckProSecurityStatus(list_cves=True)
    code, out = run_check(check, status_output(fixed_cves=2), capsys)
    assert code == 0
    first, *cves = out.split("\n")
    assert "2 CVEs fixed by Livepatch" in first
    assert "livepatch_fixed_cves=2;;;0" in first
    assert cves == ["cve-2013-0", "cve-2013-1"]


def test_livepatch_cves_are_not_listed_by_default(capsys) -> None:
    _, out = run_check(CheckProSecurityStatus(), status_output(fixed_cves=2), capsys)
    assert "\n" not in out


def test_livepatch_fixed_cves_are_shown_when_not_ok(capsys) -> None:
    output = status_output(packages=[("openssl", "upgrade_available")], fixed_cves=2)
    code, out = run_check(CheckProSecurityStatus(), output, capsys)
    assert code == 1
    assert "1 security updates available: openssl; 2 CVEs fixed by Livepatch" in out


def test_missing_livepatch_section_is_unknown(capsys) -> None:
    data = json.loads(status_output())
    del data["livepatch"]
    code, out = run_check(CheckProSecurityStatus(), json.dumps(data), capsys)
    assert code == 3
    assert "could not parse security status" in out


def test_unknown_update_status_is_unknown(capsys) -> None:
    output = status_output(packages=[("openssl", "something_new")])
    code, out = run_check(CheckProSecurityStatus(), output, capsys)
    assert code == 3
    assert "unknown update status 'something_new' for openssl" in out


@pytest.mark.parametrize(("count", "code"), [(0, 0), (2, 0), (3, 1), (6, 1), (7, 2)])
def test_update_thresholds(count, code, capsys) -> None:
    packages = [(f"pkg{i}", "upgrade_available") for i in range(count)]
    check = CheckProSecurityStatus(warning_updates=3, critical_updates=7)
    result, out = run_check(check, status_output(packages=packages), capsys)
    assert result == code
    assert f"security_updates={count};3;7;0" in out


def test_packages_are_counted_once(capsys) -> None:
    packages = [
        ("openssl", "upgrade_available"),
        ("openssl", "upgrade_available_not_preferred"),
    ]
    code, out = run_check(CheckProSecurityStatus(), status_output(packages=packages), capsys)
    assert code == 1
    assert "1 security updates available: openssl;" in out


def test_long_package_lists_are_shortened(capsys) -> None:
    packages = [(f"pkg{i}", "upgrade_available") for i in range(8)]
    _, out = run_check(CheckProSecurityStatus(), status_output(packages=packages), capsys)
    assert "8 security updates available: pkg0, pkg1, pkg2, pkg3, pkg4 and 3 more" in out


# --- reboot -----------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "code", "message"),
    [
        ("no", 0, "no reboot required"),
        ("yes-kernel-livepatches-applied", 0, "running kernel is covered by Livepatch"),
        ("yes", 1, "WARNING - reboot required;"),
        ("maybe", 3, "unknown reboot required state 'maybe'"),
    ],
)
def test_reboot_required(value, code, message, capsys) -> None:
    output = status_output(reboot_required=value)
    result, out = run_check(CheckProSecurityStatus(), output, capsys)
    assert result == code
    assert message in out


def test_worst_state_wins_and_only_affected_are_listed(capsys) -> None:
    output = status_output(
        enabled=["esm-infra"],
        reboot_required="yes",
        packages=[(f"pkg{i}", "upgrade_available") for i in range(10)],
    )
    code, out = run_check(CheckProSecurityStatus(), output, capsys)
    assert code == 2
    assert out.startswith("CRITICAL - 10 security updates available: pkg0")
    assert "reboot required" not in out


def test_critical_beats_unknown(capsys) -> None:
    output = status_output(attached=False, reboot_required="maybe")
    code, out = run_check(CheckProSecurityStatus(), output, capsys)
    assert code == 2
    assert "unknown reboot" not in out


# --- parsing ----------------------------------------------------------------


@pytest.mark.parametrize(
    "output",
    [
        "not json",
        "[]",
        "{}",
        '{"summary": {"ua": {}}, "packages": []}',
        '{"summary": {"reboot_required": "no"}, "packages": []}',
        status_output(packages=[("openssl", "upgrade_available")]).replace(
            '"package": ', '"name": '
        ),
    ],
)
def test_unparseable_output_is_unknown(output, capsys) -> None:
    code, out = run_check(CheckProSecurityStatus(), output, capsys)
    assert code == 3
    assert "could not parse security status" in out


@pytest.mark.parametrize(
    "ua",
    [
        {"attached": "yes", "enabled_services": [], "entitled_services": []},
        {"attached": True, "enabled_services": None, "entitled_services": []},
    ],
)
def test_unexpected_pro_information_is_unknown(ua, capsys) -> None:
    data = json.loads(status_output())
    data["summary"]["ua"] = ua
    code, out = run_check(CheckProSecurityStatus(), json.dumps(data), capsys)
    assert code == 3
    assert "unexpected Ubuntu Pro information" in out


# --- running the command ----------------------------------------------------


def test_run_status_returns_stdout() -> None:
    with patch("subprocess.run", return_value=completed("hello")) as run:
        assert CheckProSecurityStatus().run_status() == "hello"
    assert run.call_args.args[0] == ["pro", "security-status", "--format", "json"]


@pytest.mark.parametrize(
    "error",
    [FileNotFoundError("not found"), subprocess.TimeoutExpired("cmd", 60)],
)
def test_run_status_command_failure(error) -> None:
    with (
        patch("subprocess.run", side_effect=error),
        pytest.raises(SecurityStatusError),
    ):
        CheckProSecurityStatus().run_status()


@pytest.mark.parametrize(
    ("result", "expected"),
    [
        (completed(stderr="apt cache is broken", returncode=1), "apt cache is broken"),
        (completed(stdout="stdout text", returncode=2), "stdout text"),
        (completed(returncode=1), "no output"),
    ],
)
def test_run_status_non_zero_exit(result, expected, capsys) -> None:
    with patch("subprocess.run", return_value=result), pytest.raises(SystemExit) as exit_info:
        CheckProSecurityStatus(verbose=True).check_status()
    assert exit_info.value.code == 3
    assert expected in capsys.readouterr().out


def test_run_status_failure_exits_unknown(capsys) -> None:
    with (
        patch("subprocess.run", side_effect=FileNotFoundError("nope")),
        pytest.raises(SystemExit) as exit_info,
    ):
        CheckProSecurityStatus().check_status()
    assert exit_info.value.code == 3
    assert capsys.readouterr().out.startswith("UNKNOWN - could not run pro")


def test_end_to_end_through_subprocess(capsys) -> None:
    with (
        patch("subprocess.run", return_value=completed(status_output())),
        pytest.raises(SystemExit) as exit_info,
    ):
        CheckProSecurityStatus().check_status()
    assert exit_info.value.code == 0
    assert capsys.readouterr().out.startswith("OK - attached to Ubuntu Pro")


def test_nagios_exit_codes(capsys) -> None:
    for status, code in (("OK", 0), ("WARNING", 1), ("CRITICAL", 2), ("UNKNOWN", 3)):
        with pytest.raises(SystemExit) as exit_info:
            CheckProSecurityStatus.nagios_exit(status, "msg")
        assert exit_info.value.code == code
        assert capsys.readouterr().out == f"{status} - msg\n"


def test_nagios_exit_with_perfdata(capsys) -> None:
    with pytest.raises(SystemExit):
        CheckProSecurityStatus.nagios_exit("OK", "msg", "a=1")
    assert capsys.readouterr().out == "OK - msg | a=1\n"
