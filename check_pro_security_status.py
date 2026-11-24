#!/usr/bin/env python3

import argparse
import json
import logging
import subprocess
from typing import Any, ClassVar, NoReturn


class SecurityStatusError(RuntimeError):
    """Raised when the Pro security status cannot be obtained or evaluated."""


class CheckProSecurityStatus:
    COMMAND = "pro"
    # Reading the apt cache can take a while on large machines.
    COMMAND_TIMEOUT = 60
    DEFAULT_WARNING_UPDATES = 1
    DEFAULT_CRITICAL_UPDATES = 10
    MAX_LISTED_PACKAGES = 5
    SEVERITY: ClassVar[dict[str, int]] = {"OK": 0, "UNKNOWN": 1, "WARNING": 2, "CRITICAL": 3}
    ESM_SERVICES = ("esm-infra", "esm-apps")

    # Package update statuses that can be installed right now.
    INSTALLABLE = ("upgrade_available", "upgrade_available_not_preferred")
    # Package update statuses that exist but cannot be installed, and why.
    BLOCKED: ClassVar[dict[str, str]] = {
        "pending_attach": "need an attached Ubuntu Pro subscription",
        "pending_enable": "need an entitled ESM service to be enabled",
        "upgrade_unavailable": "are not covered by the subscription",
    }

    # summary.reboot_required values.
    REBOOT_RULES: ClassVar[dict[str, tuple[str, str]]] = {
        "no": ("OK", "no reboot required"),
        "yes-kernel-livepatches-applied": (
            "OK",
            "reboot required, the running kernel is covered by Livepatch",
        ),
        "yes": ("WARNING", "reboot required"),
    }

    def __init__(
        self,
        warning_updates: int = DEFAULT_WARNING_UPDATES,
        critical_updates: int = DEFAULT_CRITICAL_UPDATES,
        verbose: bool = False,
        list_cves: bool = False,
    ) -> None:
        self.list_cves = list_cves
        self.warning_updates = warning_updates
        self.critical_updates = critical_updates
        self.validate_thresholds()

        self.log = logging.getLogger(__name__)
        if not self.log.handlers:
            self.log.addHandler(logging.StreamHandler())
        self.log.setLevel(logging.DEBUG if verbose else logging.CRITICAL)

    def validate_thresholds(self) -> None:
        for name, value in (
            ("warning-updates", self.warning_updates),
            ("critical-updates", self.critical_updates),
        ):
            if value <= 0:
                raise ValueError(f"{name} must be greater than zero")
        if self.warning_updates > self.critical_updates:
            raise ValueError("warning-updates must not be higher than critical-updates")

    def check_status(self) -> None:
        try:
            status = self.parse_status(self.run_status())
            results = self.evaluate(status)
        except SecurityStatusError as error:
            self.nagios_exit("UNKNOWN", str(error))

        cves = status["livepatch_fixed_cves"]
        perfdata = self.perfdata(status["packages"], len(cves))
        # Informational only, never affects the state.
        info = f"{len(cves)} CVEs fixed by Livepatch"
        long_output = "\n".join(cves) if self.list_cves else ""
        worst = max(results, key=lambda result: self.SEVERITY[result[0]])[0]
        if worst == "OK":
            messages = [m for _, m in results]
        else:
            messages = [message for level, message in results if level == worst]
        self.nagios_exit(worst, "; ".join([*messages, info]), perfdata, long_output)

    def run_status(self) -> str:
        """Run `pro security-status --format json` once and return its output."""
        self.log.debug("Running: %s security-status --format json", self.COMMAND)
        try:
            result = subprocess.run(
                [self.COMMAND, "security-status", "--format", "json"],
                capture_output=True,
                text=True,
                timeout=self.COMMAND_TIMEOUT,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as error:
            raise SecurityStatusError(f"could not run {self.COMMAND}: {error}") from error

        self.log.debug(
            "Exit code %d, stdout=%r stderr=%r",
            result.returncode,
            result.stdout,
            result.stderr,
        )
        if result.returncode != 0:
            detail = (result.stderr or result.stdout).strip() or "no output"
            raise SecurityStatusError(
                f"{self.COMMAND} exited with {result.returncode}: {detail}"
            )
        return result.stdout

    @staticmethod
    def parse_status(output: str) -> dict[str, Any]:
        """Parse the JSON and check that every field the check uses is present."""
        try:
            data = json.loads(output)
            summary = data["summary"]
            ua = summary["ua"]
            status = {
                "attached": ua["attached"],
                "enabled_services": ua["enabled_services"],
                "entitled_services": ua["entitled_services"],
                "reboot_required": summary["reboot_required"],
                "livepatch_fixed_cves": [cve["name"] for cve in data["livepatch"]["fixed_cves"]],
                "packages": [
                    (package["package"], package["status"])
                    for package in data["packages"]
                ],
            }
        except (ValueError, TypeError, KeyError) as error:
            raise SecurityStatusError(
                f"could not parse security status ({error!r}): {output.strip()[:200]!r}"
            ) from error
        if not isinstance(status["attached"], bool) or not all(
            isinstance(status[key], list)
            for key in ("enabled_services", "entitled_services")
        ):
            raise SecurityStatusError(
                f"unexpected Ubuntu Pro information in security status: {ua!r}"
            )
        return status

    def evaluate(self, status: dict[str, Any]) -> list[tuple[str, str]]:
        return [
            self.evaluate_attachment(
                status["attached"],
                status["enabled_services"],
                status["entitled_services"],
            ),
            *self.evaluate_updates(status["packages"]),
            self.evaluate_reboot(status["reboot_required"]),
        ]

    def evaluate_attachment(
        self, attached: bool, enabled: list[str], entitled: list[str]
    ) -> tuple[str, str]:
        if not attached:
            return "CRITICAL", "machine is not attached to an Ubuntu Pro subscription"
        disabled = [s for s in self.ESM_SERVICES if s in entitled and s not in enabled]
        if disabled:
            return "WARNING", f"{', '.join(disabled)} entitled but not enabled"
        active = [s for s in self.ESM_SERVICES if s in enabled]
        return "OK", f"attached to Ubuntu Pro ({', '.join(active) or 'no ESM'} enabled)"

    def evaluate_updates(
        self, packages: list[tuple[str, str]]
    ) -> list[tuple[str, str]]:
        installable: set[str] = set()
        blocked: dict[str, set[str]] = {status: set() for status in self.BLOCKED}
        for name, status in packages:
            if status in self.INSTALLABLE:
                installable.add(name)
            elif status in self.BLOCKED:
                blocked[status].add(name)
            else:
                return [("UNKNOWN", f"unknown update status {status!r} for {name}")]

        results = [self.evaluate_installable(installable)]
        for status, names in blocked.items():
            if names:
                reason = self.BLOCKED[status]
                detail = f"{len(names)} security updates {reason}: {self.package_list(names)}"
                results.append(("WARNING", detail))
        return results

    def evaluate_installable(self, names: set[str]) -> tuple[str, str]:
        if not names:
            return "OK", "no security updates available"
        detail = f"{len(names)} security updates available: {self.package_list(names)}"
        if len(names) >= self.critical_updates:
            return "CRITICAL", detail
        if len(names) >= self.warning_updates:
            return "WARNING", detail
        return "OK", detail

    def evaluate_reboot(self, value: str) -> tuple[str, str]:
        if value in self.REBOOT_RULES:
            return self.REBOOT_RULES[value]
        return "UNKNOWN", f"unknown reboot required state {value!r}"

    def package_list(self, names: set[str]) -> str:
        listed = sorted(names)
        text = ", ".join(listed[: self.MAX_LISTED_PACKAGES])
        if len(listed) > self.MAX_LISTED_PACKAGES:
            text += f" and {len(listed) - self.MAX_LISTED_PACKAGES} more"
        return text

    def perfdata(self, packages: list[tuple[str, str]], livepatch_fixed_cves: int) -> str:
        installable = {name for name, status in packages if status in self.INSTALLABLE}
        blocked = {name for name, status in packages if status in self.BLOCKED}
        return (
            f"security_updates={len(installable)};"
            f"{self.warning_updates};{self.critical_updates};0 "
            f"blocked_security_updates={len(blocked)};;;0 "
            f"livepatch_fixed_cves={livepatch_fixed_cves};;;0"
        )

    @staticmethod
    def nagios_exit(
        status: str, message: str, perfdata: str = "", long_output: str = ""
    ) -> NoReturn:
        codes = {"OK": 0, "WARNING": 1, "CRITICAL": 2, "UNKNOWN": 3}
        print(f"{status} - {message}" + (f" | {perfdata}" if perfdata else ""))
        if long_output:
            print(long_output)
        raise SystemExit(codes[status])


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Check the Ubuntu Pro security status"
    )
    parser.add_argument(
        "--warning-updates",
        "-w",
        type=int,
        default=CheckProSecurityStatus.DEFAULT_WARNING_UPDATES,
        help="warn when at least this many packages have installable security "
        "updates (default: %(default)s)",
    )
    parser.add_argument(
        "--critical-updates",
        "-c",
        type=int,
        default=CheckProSecurityStatus.DEFAULT_CRITICAL_UPDATES,
        help="fail when at least this many packages have installable security "
        "updates (default: %(default)s)",
    )
    parser.add_argument(
        "--list-livepatch-cves",
        "-l",
        action="store_true",
        help="list the CVEs fixed by Livepatch, one per line, after the status line",
    )
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    try:
        check = CheckProSecurityStatus(
            args.warning_updates,
            args.critical_updates,
            args.verbose,
            args.list_livepatch_cves,
        )
    except ValueError as error:
        parser.error(str(error))
    check.check_status()


if __name__ == "__main__":  # pragma: no cover
    main()
