# Security skills and tooling for CloudGuard

Last reviewed: 2026-10-25. This is a project-specific shortlist, not an exhaustive catalog of cybersecurity products. CloudGuard is a FastAPI and Next.js container-alert triage prototype; its most important gaps are reliable telemetry, measured detection quality, and protection of its own API and dashboard. Tool availability and GitHub feature eligibility can change, so recheck the linked primary sources before adoption.

## Status and decision rule

| Status | Meaning |
|---|---|
| Installed | Available in this local Codex skill directory; new skills become available to new turns |
| Connected | Integration or plugin installed and enabled for this Codex environment |
| Candidate | Researched but not installed or configured |

Prefer a small stack that gives distinct evidence. A skill guides review; an MCP server lets an agent invoke a tool; a scanner produces findings; none proves that CloudGuard detects attacks accurately. Preserve scanner reports and triage false positives before making claims.

## Codex skills

| Skill | Status | Why it helps this repository | Use it for |
|---|---|---|---|
| [security-best-practices](https://github.com/openai/skills/blob/main/skills/.curated/security-best-practices/SKILL.md) | **Installed** in `C:/Users/Sarvesh/.codex/skills/security-best-practices` | Includes FastAPI, Next.js, React and general browser guidance, matching both services | Review ingestion validation, access control, browser/server boundaries and secure defaults before release |
| [security-threat-model](https://github.com/openai/skills/blob/main/skills/.curated/security-threat-model/SKILL.md) | **Installed** in `C:/Users/Sarvesh/.codex/skills/security-threat-model` | Grounds assets, actors, trust boundaries and abuse paths in source | Refresh [CloudGuard's threat model](THREAT_MODEL.md) after adding sensor identities, Kubernetes ingestion or response actions |
| [security-ownership-map](https://github.com/openai/skills/tree/main/skills/.curated/security-ownership-map) | Candidate | Finds sensitive code with thin reviewer coverage from Git history | Add if several contributors maintain auth, ingestion and model code; limited value while ownership is effectively one person |

The first two were installed from the official `openai/skills` curated repository with the Codex skill installer. They live in the user's Codex profile, **not** in this Git repository. This document records their purpose for future contributors but does not install them on another machine. Review the skill source and permissions before installing any third-party skill; a skill can include executable scripts or instructions that access the local environment. [MCP's skills threat model](https://github.com/modelcontextprotocol/ext-skills/blob/main/docs/threat-model.md) explains why remotely supplied skill content should be treated as untrusted.

On 2026-10-25, the installed security best-practices and threat-model skills guided the scoped API keys, bounded request bodies, server-side dashboard proxy, model artifact integrity check, and the updated [threat model](THREAT_MODEL.md). This is a design review record, not an independent vulnerability scan or runtime penetration test.

## MCP and Codex integrations

| Integration | Status | Practical use | Decision |
|---|---|---|---|
| GitHub integration | **Connected** | Repository reads/writes, reviews and CI diagnostics already available in this session | Keep using it; no duplicate GitHub MCP installation needed. GitHub's [official MCP server](https://github.com/github/github-mcp-server) is an option for other clients and supports narrow toolsets and read-only mode. |
| [Codex Security](https://github.com/openai/codex-security/blob/main/README.md) | **Installed and enabled** (`0.1.32`) | Source-backed repository scans, diff review, finding validation and saved coverage reports | Best next integration for an independent security review. Scan this repository with emphasis on authentication, Falco input, model-training permissions and incident mutations. Do not claim it has scanned this repo yet. |
| [Semgrep MCP](https://github.com/semgrep/mcp/blob/main/README.md) | Candidate | Run static rules on FastAPI/Next.js code and custom rule checks from an agent | Add only if interactive source scans become frequent; the [Semgrep CLI](https://semgrep.dev/docs/category/local-and-cli-scans) is simpler for reproducible CI. |
| [Trivy MCP](https://github.com/aquasecurity/trivy-mcp/blob/main/docs/quickstart.md) | Candidate | Agent access to dependency, image, secret and configuration scans | Add after Trivy CLI is in the security workflow; its [MCP plugin supports Windows](https://github.com/aquasecurity/trivy-mcp/blob/main/plugin.yaml). Keep any network transport bound to localhost and grant only needed access. |

Do not add generic shell-execution, web-reconnaissance, exploit or unmaintained MCP servers merely to increase the tool count. Every server increases the authority exposed to its client; prefer official publishers, local transports, narrow scopes, and reviewed updates. This is particularly relevant for a security project that may inspect untrusted alert payloads.

## Conventional security tools and reference frameworks

| Priority | Tool/source | Gap it addresses | First useful output |
|---|---|---|---|
| P0 | [GitHub CodeQL default setup](https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/configure-code-scanning/configure-code-scanning) | Static analysis for Python and JavaScript/TypeScript | Triage findings against reachable code; verify repository eligibility and settings before enabling |
| P0 | [Dependabot alerts](https://docs.github.com/en/code-security/how-tos/secure-your-supply-chain/secure-your-dependencies/configure-dependabot-alerts) and [secret scanning/push protection](https://docs.github.com/en/code-security/getting-started/github-security-features) | Known vulnerable dependencies and committed credentials | Review alert state; rotate any real leaked key rather than only deleting it from a commit |
| P0 | [Trivy filesystem scan](https://trivy.dev/docs/dev/target/filesystem/) and image scan | Vulnerabilities, secrets, misconfiguration and SBOMs for both Docker images | Reproducible scan report for each image and source tree; triage severity and reachability |
| P1 | [Semgrep Community Edition](https://semgrep.dev/products/community-edition/) | Source patterns and project-specific secure-code rules | Baseline report plus a small set of reviewed custom rules |
| P1 | [OSV-Scanner](https://github.com/google/osv-scanner/blob/main/docs/scan-source.md) | Independent dependency check from lockfiles/SBOMs | Findings for `frontend/package-lock.json`; check Python dependency resolution too |
| P1 | [Falco rule guidance](https://falco.org/docs/concepts/rules/style-guide/) and [output channels](https://falco.org/docs/concepts/outputs/) | Real Linux/Kubernetes alert quality and schema reliability | Captured Falco JSON fixtures, missing-field counts, dropped-event metrics and a repeatable live demo |
| P1 | [OWASP ASVS](https://asvs.owasp.org/) | Testable security requirements for the dashboard and API | Requirement checklist for auth, access control, logging and input handling, with evidence links |
| P1 | [MITRE ATT&CK Containers](https://attack.mitre.org/matrices/enterprise/containers/) | Honest coverage mapping | A matrix of technique, required data, active sensor, rule and positive/benign replay result |
| P2 | [OpenSSF Scorecard](https://github.com/ossf/scorecard) and [Sigstore Cosign](https://docs.sigstore.dev/cosign/verifying/verify/) | Repository and image supply-chain assurance | Scorecard issues, signed image digest and verified build provenance |

GitHub's features are repository settings, not part of the source tree. Their availability depends on repository visibility, plan and permissions. No CodeQL, Dependabot, secret-scanning, Trivy, Semgrep or OSV scan was run as part of this tooling survey; their rows are recommendations, not passing results.

## Recommended order for a credible college demonstration

1. **Show a real input path.** Capture Falco alerts on a Linux test host and replay the captured JSON. Include sensor heartbeat, parse failures and dropped-event counters. This is the most important proof that the system is more than a simulator.
2. **Show measured detection quality.** Keep benign and attack traces separate from training data. Report per-scenario precision/recall, false alerts per container-hour, detection latency and ingestion loss as specified in [the college delivery plan](../COLLEGE_PROJECT_PLAN.md).
3. **Secure CloudGuard itself.** Use the installed review and threat-model skills plus Codex Security. Address telemetry-writer versus analyst permissions, rate limits, audit logging and TLS from [the concept roadmap](CYBERSECURITY_CONCEPTS.md).
4. **Automate repeatable checks.** Add CodeQL, dependency/secret scans and a Trivy image scan to CI when the corresponding deployment and permission decisions are made. Save outputs with the demo evidence; a green scan is a coverage signal, not a guarantee.
5. **Make the result judgeable.** Maintain a coverage table linking each detection to a real field, a Falco sample, a benign control and a measured outcome. Keep unsupported claims explicitly marked as future work.

## Maintenance

When a tool is installed or connected, change its status and record the version, source, permissions, operator and first successful run. For scanners, record the command or workflow, target revision, date, report location, exclusions and triage result. For a new detection data source, also update [the detection catalog](DETECTION_CATALOG.md), [threat model](THREAT_MODEL.md) and [concept roadmap](CYBERSECURITY_CONCEPTS.md). Never publish raw credentials or sensitive alert payloads in this document.
