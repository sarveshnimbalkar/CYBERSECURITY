# CloudGuard detection catalog

Last reviewed: 2026-10-24. Implementation: `backend/app/detection/rules.py`; orchestration: `backend/app/services/event_service.py`; synthetic cases: `backend/app/telemetry/simulator.py`.

An alert means a condition matched. It does **not** establish attacker intent or successful compromise. ATT&CK IDs are investigation hypotheses supported by the listed evidence; they are not labels for every event with the same fields. Falco's own alert is recorded separately as `FALCO-001`, and optional ML scoring as `ML-001`.

| Rule | Evidence required | Main false-positive case / tuning | ATT&CK hypothesis |
|---|---|---|---|
| RULE-001 Suspicious shell | `PROCESS_EXEC`/`SHELL_EXEC` plus shell name; parent/root raises severity | Maintenance/debug shells; allowlist by image, process parent, and operator | [T1059.004](https://attack.mitre.org/techniques/T1059/004/) |
| RULE-002 Reverse-shell indicator | Shell network connection or outbound connection after a shell in the same container | Legitimate shell-based health checks; correlate exact PID, process ancestry, destination, and time | [T1059](https://attack.mitre.org/techniques/T1059/) is indicative; reverse access is not proven |
| RULE-003 Privilege-change indicator | `PRIV_CHANGE`, root execution of suspicious process, or `sudo`/`su` command | Root is common in legacy containers; compare prior UID/capabilities and approved process | No ID: current evidence does not show vulnerability exploitation |
| RULE-004 Unusual external destination | External IP and unusual port, or an IP outside a configured destination allowlist | Custom application ports and incomplete allowlists; tune per service | No ID: connection alone does not prove C2 or exfiltration |
| RULE-005 Cryptomining indicator | Miner process name, or high CPU with a mining-associated port | Legitimate high CPU and shared ports; require duration, destination reputation, and workload baseline | [T1496](https://attack.mitre.org/techniques/T1496/) |
| RULE-006 Rapid file modification | More than 50 file events/minute in one container, or sensitive-path modification | Backups, builds, and log rotation; use per-process rate and workload baseline | No ID: modification volume alone does not prove encryption |
| RULE-007 Runtime socket access | In-container access to Docker/containerd/CRI-O management socket | Approved monitoring/build tools; allowlist explicit image and socket mount | [T1611](https://attack.mitre.org/techniques/T1611/) opportunity; escape is not proven |
| RULE-008 Credential file access | `FILE_READ` of service-account token, cloud credentials, kubeconfig, or `/etc/shadow` | Apps legitimately reading mounted secrets; compare reader executable and expected use | [T1552.001](https://attack.mitre.org/techniques/T1552/001/) |
| RULE-009 Cron persistence change | Create/modify cron configuration inside a container | Image setup or maintenance; compare with approved image and deployment window | [T1053.003](https://attack.mitre.org/techniques/T1053/003/) |
| RULE-010 Security artifact tampering | Delete log file or modify/delete Falco/audit configuration | Log rotation and planned agent updates; require actor/process context | [T1070.004](https://attack.mitre.org/techniques/T1070/004/) only for log deletion |

## Required telemetry contract

- Core: event type, timestamp, container ID, host, source, process name/PID, parent, UID, command line.
- File: operation, absolute path, actor process, and preferably inode/hash and mount information.
- Network: process identity, destination IP/port, protocol, byte counts, and connection direction.
- Container: image digest, privilege/capabilities, namespace, workload name, and deployment identity.
- Sensor: Falco rule, priority, raw fields, sensor version, collection time, and dropped-event count.

The Falco JSON adapter maps `open`/`openat` to a read or modification event **only when `evt.arg.flags` identifies the mode**. Other open alerts remain `FALCO_ALERT` and retain the raw evidence. Add fields to Falco output rules when they are missing. See [Falco's output-field reference](https://falco.org/docs/reference/rules/supported-fields/).

## Review checklist for each rule

1. Reproduce the positive case with a captured event and verify the listed fields are present.
2. Replay benign traffic from several workloads and record false positives per container-hour.
3. Confirm the incident shows raw evidence, rule ID, confidence, severity, and the correct source label.
4. Verify a missing field does not silently become a strong accusation.
5. Version the rule and update its allowlist or threshold with an owner and reason.

The current integration check proves the synthetic scenarios trigger expected rule IDs. It does not establish accuracy on production traffic.
