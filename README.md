# CloudVerse Windows Data Center Collector

Outbound-only collector for Microsoft Hyper-V and System Center Virtual Machine Manager. It inventories immutable host/VM/storage/network topology, captures Hyper-V performance counters, creates Ed25519-signed canonical bundles, encrypts its bounded local spool with AES-256-GCM, and uploads to the CloudVerse control plane or exports signed bundles for offline import.

SCVMM mode supplies inventory only. Hyper-V performance is deliberately collected at the host boundary, where native counter instances can be reconciled to immutable VM GUIDs. An SCVMM-only worker emits an explicit host-collector-required gap and never attributes its own local counters to the managed estate.

## Trust boundary

The runtime never accepts inbound commands. PowerShell execution is limited to the immutable command catalog, exact packaged scripts, `AllSigned`, approved signer thumbprints, and the canonical Windows PowerShell executable. The selected execution boundary is explicit: WDAC/AppLocker must place direct execution in `ConstrainedLanguage`, while the supplied JEA endpoint exposes four fixed functions to the collector in `NoLanguage`. Source checkouts are intentionally unsigned and cannot pass the production release gate.

The install script requires its own valid Authenticode signature and an exact release archive SHA-256. SCVMM with JEA requires a dedicated domain gMSA so the constrained endpoint can authenticate to the VMM network resource; local Hyper-V JEA uses a temporary virtual run-as account. Interactive user accounts are not supported. The installed scheduled task runs at startup with limited privileges and restart policy. Its identity has read/execute—not write—access to code and configuration; absolute state, spool and optional export directories live outside the install tree with separate writable ACLs. Secrets remain in the ACL-restricted state directory and only public enrollment material leaves the estate.

## Lifecycle

1. Download a tagged release and verify its GitHub artifact attestation and SHA-256.
2. Have the enterprise-approved code-signing pipeline Authenticode-sign all operational `.ps1` files, both installers, and every packaged JEA `.ps1`, `.psm1`, `.psd1`, and `.psrc` asset with the same certificate. Then run `New-CloudVerseReleaseManifest.ps1` to generate `release-manifest.json` with exact post-signing operation hashes and signer thumbprints. Repack the candidate contents at the ZIP root under the final name `cloudverse-windows-collector.zip`; do not add another parent directory.
3. Select `executionBoundary.kind` in the collector configuration. For `JEA`, give an endpoint name; the signed installer creates the supplied `NoLanguage` endpoint and verifies every JEA asset against its own signer. For `WDAC_APPLOCKER`, deploy policy that makes direct Windows PowerShell report `ConstrainedLanguage`.
4. Run `cloudverse-windows-collector enroll` once with the short-lived enrollment token in a file. The file is consumed after successful enrollment.
5. Run the signed installer using the exact archive digest and a dedicated service account.

The candidate includes the exact Windows Node.js runtime used by CI, its license,
production-only dependencies and an SPDX dependency SBOM. The installer rejects
packages missing the runtime, SBOM, signed-operation set or generated release
manifest before registering the startup task.

No endpoint URL or platform credentials are entered into the CloudVerse browser wizard. The wizard creates the short-lived enrollment package; the installed in-estate agent supplies discovery/auth/health evidence over the outbound channel.
