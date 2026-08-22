# CloudVerse Windows Data Center Collector

Outbound-only collector for Microsoft Hyper-V and System Center Virtual Machine Manager. It inventories immutable host/VM/storage/network topology, captures Hyper-V performance counters, creates Ed25519-signed canonical bundles, encrypts its bounded local spool with AES-256-GCM, and uploads to the CloudVerse control plane or exports signed bundles for offline import.

## Trust boundary

The runtime never accepts inbound commands. PowerShell execution is limited to the immutable command catalog, exact packaged scripts, `AllSigned`, approved signer thumbprints, the canonical Windows PowerShell executable, and a ConstrainedLanguage host established by WDAC/AppLocker or JEA. Source checkouts are intentionally unsigned and cannot pass the production release gate.

The install script requires its own valid Authenticode signature and an exact release archive SHA-256. A dedicated gMSA or virtual service account is required; interactive user accounts are not supported. The installed scheduled task runs at startup with limited privileges and restart policy. Secrets remain in the ACL-restricted state directory and only public enrollment material leaves the estate.

## Lifecycle

1. Download a tagged release and verify its GitHub artifact attestation and SHA-256.
2. Have the enterprise-approved code-signing pipeline Authenticode-sign all operational `.ps1` files and the installer, then generate the release manifest with exact script hashes and signer thumbprints.
3. Configure WDAC/AppLocker or the supplied JEA boundary so Windows PowerShell reports `ConstrainedLanguage`.
4. Run `cloudverse-windows-collector enroll` once with the short-lived enrollment token in a file. The file is consumed after successful enrollment.
5. Run the signed installer using the exact archive digest and a dedicated service account.

No endpoint URL or platform credentials are entered into the CloudVerse browser wizard. The wizard creates the short-lived enrollment package; the installed in-estate agent supplies discovery/auth/health evidence over the outbound channel.
