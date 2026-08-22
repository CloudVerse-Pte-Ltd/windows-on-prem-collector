# Source provenance

This repository is the implementation authority for the CloudVerse Windows data-center collector.

The release layout was informed by a read-only review of CloudVerse's existing public Go-agent publishing pattern: source and build instructions live together, CI uses immutable action revisions, tagged artifacts are checksummed, and provenance is attached to the artifact. No file, branch, workflow, tag, release, or repository setting in `autonomous-kubernetes-optimization` was changed.

Transport contracts intentionally match the independently published `cloudverse-data-center-collector` protocol: one-time enrollment, locally generated Ed25519 identity, signed schema `1.0` bundles, bounded AES-256-GCM spool, outbound HTTPS upload, and offline export. Windows-specific execution and release security remains owned here.
