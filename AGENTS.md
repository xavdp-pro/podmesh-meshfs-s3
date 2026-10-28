# AGENTS — Human-AI Tandem Operating Contract for `podmesh-meshfs-s3` (v2.3.0)

## 1. AI-First Installation & Configuration
For complete headless installation, zero-touch credential discovery, CLI/UDS JSON contracts, and S3 REST API usage, read **[`AI_INSTALL_AND_CONFIG.md`](AI_INSTALL_AND_CONFIG.md)** first.

## 2. Key Paths on Debian 13 (Trixie)
- **Binary**: `/usr/bin/meshfs-s3`
- **Systemd Unit**: `/usr/lib/systemd/system/meshfs-s3.service`
- **Credentials (`0600`)**: `/etc/meshfs/s3.env` (`MESHFS_S3_ACCESS_KEY`, `MESHFS_S3_SECRET_KEY`)
- **Configuration (`0600`)**: `/etc/meshfs/s3.json`
- **Control Socket (`0600`)**: `/var/lib/meshfs/s3.sock`
- **Shared CAS Pool (`0700`)**: `/var/lib/meshfs/chunks/`
- **S3 Manifests & Multipart Store (`0700`)**: `/var/lib/meshfs/s3/`

## 3. Companion Qualification Repository
All live lab qualification reports and empirical proofs on `pve-cluster-a` (`10.10.10.210`) and `pve-cluster-b` (`10.10.10.211`) are recorded in **`xavdp-pro/podmesh-meshfs-s3-lab`** (`/home/zaza/Bureau/SHAPER-PHOENIX/LAB/REPOSITORIES/podmesh-meshfs-s3-lab`).
