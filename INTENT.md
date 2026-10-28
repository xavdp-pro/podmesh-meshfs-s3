# INTENT — `podmesh-meshfs-s3` (v2.3.0)

## Why `podmesh-meshfs-s3` Exists

`podmesh-meshfs-s3` is the **Sovereign S3-Compatible Object Storage Gateway (`meshfs-s3`)** for the PodMesh and MeshFS ecosystem.

Traditional object storage systems (MinIO, Ceph RGW, Cubbit) enforce isolated storage silos that duplicate data already stored in virtual machine disks or backup archives, consume gigabytes of RAM, or depend on external cloud coordinators.

`podmesh-meshfs-s3` eliminates that duplication by projecting a standard **Amazon S3 REST API** (`127.0.0.1:9000` + Unix socket `/var/lib/meshfs/s3.sock`) directly over the **MeshFS 4 MiB SHA-256 Content-Addressable Storage (CAS) Pool** (`/var/lib/meshfs/chunks/`):

1. **Universal Cross-Protocol Deduplication (S3 $\leftrightarrow$ POSIX $\leftrightarrow$ PMBS)**:
   Every S3 object uploaded to `meshfs-s3` is split into 4 MiB chunks indexed by their SHA-256 digest in `/var/lib/meshfs/chunks/`. Any 4 MiB block already present in a Proxmox VE virtual disk, a Podman container volume, or another S3 bucket requires **zero physical disk writes**.
2. **$\mathcal{O}(1)$ Multipart Upload Sealing**:
   Completing a multi-gigabyte S3 Multipart Upload (`CompleteMultipartUpload`) does not copy or concatenate data bytes on disk; it concatenates the ordered SHA-256 chunk descriptor vectors in memory and atomically seals the Merkle manifest in $< 2\text{ ms}$.
3. **Direct CAS Chunk Slicing (`HTTP 206 Partial Content`)**:
   `Range: bytes=start-end` requests compute the exact intersecting 4 MiB chunks, verify their SHA-256 digests against bit-rot, and stream only the requested byte window.
4. **Fail-Closed WORM Object Lock & Presigned URLs**:
   Supports S3 `COMPLIANCE` / `GOVERNANCE` retention locks (`x-amz-object-lock-retain-until-date`) that reject deletion or overwrite with `403 Forbidden (ObjectLocked)`, and generates time-bounded HMAC-SHA256 presigned URLs for zero-trust AI agent delegation.
