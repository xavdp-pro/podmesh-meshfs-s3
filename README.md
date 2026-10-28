# `podmesh-meshfs-s3` (`v2.3.0`) — Sovereign S3 Gateway on MeshFS 4 MiB CAS

`podmesh-meshfs-s3` (`/usr/bin/meshfs-s3`) is the **Pure Rust S3-Compatible Object Storage Gateway** for the PodMesh and MeshFS ecosystem on Debian 13 (Trixie) and Proxmox VE 9.x.

> **AI-First Autonomous Deployment**: Read **[`AI_INSTALL_AND_CONFIG.md`](AI_INSTALL_AND_CONFIG.md)** for zero-touch APT installation, CSPRNG credential bootstrap, Unix socket IPC (`/var/lib/meshfs/s3.sock`), and S3 REST API contracts.

---

## Key Capabilities

1. **Universal Cross-Protocol Deduplication (`/var/lib/meshfs/chunks/`)**:
   - Shares the exact same 4 MiB SHA-256 Content-Addressable Storage (CAS) chunk store as [`podmesh-meshfs`](https://github.com/xavdp-pro/podmesh-meshfs).
   - Objects uploaded via S3 are automatically deduplicated at 4 MiB block granularity against Proxmox VE VM disks, Podman container volumes, and other S3 buckets.
2. **$\mathcal{O}(1)$ Multipart Upload Completion**:
   - `CreateMultipartUpload`, `UploadPart`, and `CompleteMultipartUpload` assemble multi-gigabyte objects in $< 2\text{ ms}$ by concatenating SHA-256 chunk descriptor lists in the Merkle manifest without rewriting payload bytes on disk.
3. **Direct Chunk Slicing (`HTTP 206 Partial Content`)**:
   - `Range: bytes=start-end` requests read only the intersecting 4 MiB CAS chunks and verify SHA-256 integrity on every chunk read.
4. **WORM Object Lock (`COMPLIANCE` / `GOVERNANCE`)**:
   - Enforces immutable retention (`x-amz-object-lock-retain-until-date`), rejecting any `DELETE` or overwrite attempt with `HTTP 403 Forbidden (ObjectLocked)`.
5. **HMAC-SHA256 Presigned URLs**:
   - Generates time-bounded, method-bound presigned URLs (`meshfs-s3 presign`) for zero-trust delegation to external clients and AI agents.

---

## Quick Install on Debian 13 (Trixie)

```bash
sudo apt-get update
sudo apt-get install -y podmesh-meshfs podmesh-meshfs-s3
```

---

## Repository Structure

- `src/main.rs` — Pure Rust `meshfs-s3` S3 REST server (`axum`), shared 4 MiB SHA-256 CAS engine, UDS control server, and CLI.
- `packaging/build-deb-meshfs-s3.sh` — Reproducible Debian 13 `.deb` builder (`podmesh-meshfs-s3_2.3.0_amd64.deb`).
- `AI_INSTALL_AND_CONFIG.md` — 100% headless AI-First installation and configuration specification.
- `INTENT.md`, `LAW.md`, `LINEAGE.md`, `AGENTS.md`, `DEDICATION.md`, `LICENSE`.
