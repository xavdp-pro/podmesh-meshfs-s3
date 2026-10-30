# LAW — Architectural & Mathematical Invariants of `podmesh-meshfs-s3` (v2.4.1)

1. **Universal CAS Isomorphism ($\Omega_{\text{CAS}}$)**:
   - Every S3 object $O = (B, K)$ is represented as an atomic JSON Merkle manifest $\mathcal{M}_{B,K}$ referencing immutable $\le 4\text{ MiB}$ SHA-256 chunks in `/var/lib/meshfs/chunks/<prefix>/<blake3>`.
   - Silent data corruption (bit-rot) is impossible: every chunk read verifies $\text{SHA256}(\text{bytes}) \equiv h_i$ before streaming to the client.
2. **Atomic Crash-Safe Persistence**:
   - Both CAS chunks and S3 object manifests are written to temporary files (`*.tmp.<pid>.<seq>`), flushed via `sync_all()` (`fsync`), and promoted via atomic POSIX `rename()` followed by parent directory `sync_all()`.
3. **$\mathcal{O}(1)$ Multipart Completion**:
   - `CompleteMultipartUpload` operates strictly on chunk reference lists $\vec{\mathcal{C}}_{\text{final}} = \bigoplus_{p=1}^m \vec{\mathcal{C}}_p$, achieving $\mathcal{O}(1)$ disk I/O with respect to payload size.
4. **Fail-Closed WORM Immutability (`Object Lock`)**:
   - If an object manifest contains `retain_until` ($\tau_{\text{WORM}}$) where $t_{\text{now}} < \tau_{\text{WORM}}$, any `DELETE` or overwrite `PUT` MUST immediately fail closed with `HTTP 403 Forbidden` (`ObjectLocked`).
5. **Zero-Touch Cryptographic Bootstrap & Enclave Isolation (GEM-001)**:
   - By default, `meshfs-s3` binds to `127.0.0.1:9000` and `/var/lib/meshfs/s3.sock` (`0600`).
   - Enclave directories `/etc/meshfs` and `/var/lib/meshfs/s3` enforce mode `0700`.
   - `DEBIAN/postinst` idempotently provisions CSPRNG credentials (`MESHFS_S3_ACCESS_KEY` and `MESHFS_S3_SECRET_KEY`) in `/etc/meshfs/s3.env` (`0600`) without overwriting existing credentials on upgrade.
6. **Bounded Repair & Retry Discipline (Rule 38)**:
   - Transient network/socket operations are bounded to $k \le 2$ retries; semantic invariant rejections (`403 ObjectLocked`, `403 SignatureDoesNotMatch`, `409 BucketNotEmpty`) enforce $k = 0$ retries.
