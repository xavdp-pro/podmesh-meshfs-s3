# AI-First Installation & Configuration Guide — `podmesh-meshfs-s3` (`v2.3.0`)

This document provides the **100% headless, deterministic AI-First operating contract** for installing, bootstrapping, configuring, and verifying **`podmesh-meshfs-s3`** (`/usr/bin/meshfs-s3`) on Debian 13 (Trixie) and Proxmox VE 9.x without any web UI.

---

## 1. Zero-Touch Installation via Signed APT Repository (`deb.xavdp.pro`)

```bash
sudo install -d -m 0755 /etc/apt/keyrings
curl -fsSL https://deb.xavdp.pro/keys/xavdp-archive-keyring.gpg \
  | sudo tee /etc/apt/keyrings/xavdp.gpg > /dev/null
sudo chmod 0644 /etc/apt/keyrings/xavdp.gpg
printf '%s\n' 'deb [signed-by=/etc/apt/keyrings/xavdp.gpg] https://deb.xavdp.pro/podmesh trixie-stable main' \
  | sudo tee /etc/apt/sources.list.d/podmesh.list
sudo apt-get update
sudo apt-get install -y podmesh-meshfs podmesh-meshfs-s3
```

### What `postinst` Automatically Provisions
1. Creates `/etc/meshfs` (`0700`), `/var/lib/meshfs/chunks` (`0700`), and `/var/lib/meshfs/s3/{buckets,multipart}` (`0700`).
2. Atomically generates 256-bit CSPRNG S3 credentials in `/etc/meshfs/s3.env` (`0600`) if not already present:
   - `MESHFS_S3_ACCESS_KEY=PM...`
   - `MESHFS_S3_SECRET_KEY=...`
   - `MESHFS_S3_BIND=127.0.0.1:9000`
3. Enables and starts `meshfs-s3.service` listening on `127.0.0.1:9000` and `/var/lib/meshfs/s3.sock` (`0600`).

---

## 2. Deterministic Post-Install Verification (< 1s)

```bash
meshfs-s3 --version
systemctl is-active meshfs-s3.service
meshfs-s3 status
curl -fsS http://127.0.0.1:9000/healthz
```

Expected JSON output from `meshfs-s3 status`:
```json
{
  "bind_addr": "127.0.0.1:9000",
  "buckets": [],
  "cas_chunk_count": 0,
  "cas_chunks_dir": "/var/lib/meshfs/chunks",
  "s3_dir": "/var/lib/meshfs/s3",
  "service": "meshfs-s3",
  "status": "ok",
  "version": "2.3.0"
}
```

---

## 3. Deterministic CLI Operations (`meshfs-s3`)

```bash
# 1. Create and list buckets
meshfs-s3 bucket create analytics
meshfs-s3 bucket list

# 2. Ingest an object into the shared MeshFS 4 MiB CAS pool (with optional WORM retention lock)
meshfs-s3 object put analytics models/weights.bin /path/to/weights.bin \
  --retain-until "2027-01-01T00:00:00Z"

# 3. List objects in bucket
meshfs-s3 object ls analytics

# 4. Retrieve full object or byte range
meshfs-s3 object get analytics models/weights.bin /tmp/restored.bin
meshfs-s3 object get analytics models/weights.bin /tmp/slice.bin --range 0-4095

# 5. Generate an HMAC-SHA256 Presigned URL (valid 900 seconds)
meshfs-s3 presign analytics models/weights.bin --expires 900 --method GET --json
```

---

## 4. Standard S3 HTTP REST API Usage (`127.0.0.1:9000`)

Load the auto-generated credentials from `/etc/meshfs/s3.env`:
```bash
source /etc/meshfs/s3.env

# Create Bucket
curl -fsS -X PUT "http://127.0.0.1:9000/backups" \
  -H "x-amz-access-key: ${MESHFS_S3_ACCESS_KEY}" \
  -H "x-amz-secret-key: ${MESHFS_S3_SECRET_KEY}"

# Put Object with WORM Object Lock
curl -fsS -X PUT "http://127.0.0.1:9000/backups/db.sql.zst" \
  -H "x-amz-access-key: ${MESHFS_S3_ACCESS_KEY}" \
  -H "x-amz-secret-key: ${MESHFS_S3_SECRET_KEY}" \
  -H "x-amz-object-lock-mode: COMPLIANCE" \
  -H "x-amz-object-lock-retain-until-date: 2027-01-01T00:00:00Z" \
  --data-binary @/path/to/db.sql.zst

# Partial Range Read (HTTP 206 Partial Content)
curl -fsS -H "Range: bytes=0-1023" \
  -H "x-amz-access-key: ${MESHFS_S3_ACCESS_KEY}" \
  -H "x-amz-secret-key: ${MESHFS_S3_SECRET_KEY}" \
  "http://127.0.0.1:9000/backups/db.sql.zst" -o /tmp/head.bin
```
