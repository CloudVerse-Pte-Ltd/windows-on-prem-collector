# Windows collector security model

The collector is an outbound-only Windows service. It has no listener, interactive shell, generic command endpoint, dynamic module loading or user-selected script path. A compromise of SaaS configuration must not turn it into remote PowerShell execution.

## Trust boundaries and controls

| Threat | Required control and failure behavior |
|---|---|
| User-controlled command/script injection | Closed operation IDs; exact parameter schemas; `execFile` argument arrays; no shell concatenation; unknown input rejects before process creation. |
| Script/package substitution | Release-manifest SHA-256 plus valid Authenticode signer thumbprint; regular non-symlink packaged file; signed package provenance. Any mismatch prevents service readiness. |
| PowerShell policy bypass | Machine WDAC/AppLocker or JEA endpoint is mandatory and selected explicitly. `AllSigned` is defense in depth, not the sole boundary. Direct execution requires `ConstrainedLanguage`; JEA requires `NoLanguage`, exposes only the four versioned catalog functions plus a fixed boundary-health probe, and records ACL-protected transcripts. The installer verifies all JEA assets share its approved signer. |
| Excess SCVMM privilege | Dedicated `ReadOnlyAdmin` scope; discovery records visible role and bounded host-read probe. Mutation commands are absent and AST policy rejects them. |
| Telemetry misattribution | SCVMM inventory and host-level performance evidence remain separate. Native Hyper-V counters run only on the host collector; an SCVMM-only worker emits a typed gap and never treats its own counters or VMM summaries as host evidence. |
| Credential theft | SCVMM JEA runs as the least-privilege domain gMSA required for network authentication; local Hyper-V JEA uses an ephemeral virtual account. No password CLI argument, output, bundle, transcript or config export. Redaction is defense in depth. |
| Lateral movement | Exact SCVMM host/port and CPD HTTPS egress; no inbound rule; service account denied interactive logon; no arbitrary remoting. |
| Replay/tenant substitution | C06 tenant-bound Ed25519 envelope, bundle/nonce replay ledger and quarantine. |
| Transport-token theft | Generate the 256-bit token inside the collector boundary, store it in the service credential file, and enroll only its lowercase SHA-256 hash. CPD requires both this bearer proof and the Ed25519 signature. |
| Collector or SaaS outage | Encrypted bounded C36 spool; explicit backpressure; no oldest-item deletion. |

## Deployment gate

Security acceptance requires: signed release/package verification; Windows AST policy pass; JEA/WDAC or AppLocker policy export; service-account rights and denied-interactive-logon evidence; firewall proof of no inbound/exact outbound; transcript configuration; injection/redaction tests; and a live SCVMM read-only discovery where a mutation canary is demonstrably unavailable. Source scripts in Git are intentionally unsigned; only release artifacts signed by the approved certificate may run.

## Incident response

Stop the service and egress, preserve the encrypted spool and transcripts, revoke CPD and script-signing identities as applicable, compare package/digest/signature to the release record, and resume only from an approved signed package. Never weaken AllSigned, the signer allowlist, WDAC/JEA or endpoint restrictions to restore service.
