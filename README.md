# Check_Pro_Security_Status

Icinga/Nagios plugin that checks the Ubuntu Pro security status (`pro security-status`). It requires Python >=3.12 and has no third-party runtime dependencies.

The check runs the client once and evaluates the Ubuntu Pro attachment, the ESM services, the pending security updates and the reboot state of that single output. The worst state wins. The JSON fields are taken from the [Ubuntu Pro client source](https://github.com/canonical/ubuntu-pro-client/blob/main/uaclient/security_status.py) (`_schema_version` 0.1).

It complements [check_canonical_livepatch_status](https://github.com/conFrituur/check_canonical_livepatch_status): this check looks at the installed packages, the Livepatch check looks at the running kernel and the Livepatch client health.

>**AI NOTICE:** This code was derived from my other check plugins and altered with AI.

## What it checks

| Item | Result |
|---|---|
| Machine not attached to Ubuntu Pro | CRITICAL |
| `esm-infra` or `esm-apps` is in your subscription but not enabled | WARNING |
| Security updates you can install now | WARNING from `-w` (default 1), CRITICAL from `-c` (default 10) |
| Security fixes that exist but can't be installed (not attached, ESM service not enabled, or not in the subscription) | WARNING |
| `reboot_required: yes` | WARNING |
| `reboot_required: yes-kernel-livepatches-applied` | OK, with a note |
| Unknown update status, unknown reboot value or unexpected JSON | UNKNOWN |

## Usage

```console
foo@bar:~$ uv run check_pro_security_status.py --help
usage: check_pro_security_status.py [-h] [--warning-updates WARNING_UPDATES]
                                    [--critical-updates CRITICAL_UPDATES]
                                    [--list-livepatch-cves] [--verbose]

Check the Ubuntu Pro security status

options:
  -h, --help            show this help message and exit
  --warning-updates, -w WARNING_UPDATES
                        warn when at least this many packages have installable security updates
                        (default: 1)
  --critical-updates, -c CRITICAL_UPDATES
                        fail when at least this many packages have installable security updates
                        (default: 10)
  --list-livepatch-cves, -l
                        list the CVEs fixed by Livepatch, one per line, after the status line
  --verbose, -v
```

The plugin always runs `pro security-status --format json` directly (it does not call sudo). The command works as a normal user.

The update counts come from the local apt cache, so they are only as fresh as the last `apt update` (for example by `unattended-upgrades` or `apt-daily.timer`).

## States

| Level | Output |
|---|---|
| OK | attached with the entitled ESM services enabled; fewer installable security updates than `-w`; no reboot required, or a reboot required while the running kernel is covered by Livepatch |
| WARNING | an entitled ESM service (`esm-infra`, `esm-apps`) is not enabled; at least `-w` packages with installable security updates; security updates that cannot be installed (Pro not attached, ESM service not enabled, or not covered by the subscription); reboot required |
| CRITICAL | machine is not attached to an Ubuntu Pro subscription; at least `-c` packages with installable security updates |
| UNKNOWN | client cannot be run or exits non-zero; output is not the expected JSON; unrecognized update status or reboot state |

Updates count packages, not versions: a package with both a standard and an ESM update counts once.

Performance data: `security_updates` (installable, with the `-w`/`-c` thresholds) and `blocked_security_updates` (fixes that exist but cannot be installed), and `livepatch_fixed_cves` (number of CVEs fixed by Livepatch, informational only: it is also shown in the output but never changes the state).

Example output:

```
OK - attached to Ubuntu Pro (esm-infra, esm-apps enabled); no security updates available; no reboot required ; 0 CVEs fixed by Livepatch | security_updates=0;1;10;0 blocked_security_updates=0;;;0 livepatch_fixed_cves=0;;;0
WARNING - 2 security updates available: libssl3, openssl ; 0 CVEs fixed by Livepatch | security_updates=2;1;10;0 blocked_security_updates=0;;;0 livepatch_fixed_cves=0;;;0
CRITICAL - machine is not attached to an Ubuntu Pro subscription ; 0 CVEs fixed by Livepatch | security_updates=1;1;10;0 blocked_security_updates=1;;;0 livepatch_fixed_cves=0;;;0
```

## Icinga CheckCommand

```icinga2
object CheckCommand "pro-security-status" {
    import "plugin-check-command"
    command = [ PluginDir + "/check_pro_security_status.py" ]
    arguments += {
        "--warning-updates" = "$pro_security_warning_updates$"
        "--critical-updates" = "$pro_security_critical_updates$"
        "--list-livepatch-cves" = {
            set_if = "$pro_security_list_livepatch_cves$"
        }
    }
}
```
