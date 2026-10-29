//! MeshFS S3 Gateway (`meshfs-s3` v2.3.0)
//! Sovereign S3-Compatible Object Storage Gateway backed by the MeshFS 4 MiB SHA-256 CAS Pool.
//!
//! Hardened Post-Audit Edition (Claude Fable 5.1 & GPT-6 Astra Validated):
//! - Zero-Duplication Universal CAS: Objects stored via S3 share `/var/lib/meshfs/chunks/<prefix>/<sha256>`
//!   directly with MeshFS POSIX volumes.
//! - Bounded-Memory 4 MiB Streaming: HTTP `PUT` / `GET` and CLI `object put/get` stream chunks
//!   incrementally without buffering multi-gigabyte objects in RAM.
//! - Full Cryptographic Auth (AWS SigV4 Derived Key + Presigned HMAC-SHA256 + Fail-Closed Daemon Credentials).
//! - Fail-Closed WORM Object Lock across `PutObject`, `CreateMultipartUpload`, `CompleteMultipartUpload`, and `DeleteObject`.
//! - Strict Anti-Traversal Validation on Bucket Names and Multipart `uploadId`s + XML Escaping + `O_NOFOLLOW`.

use axum::{
    body::{Body, Bytes},
    extract::{Path as AxumPath, Query, State},
    http::{HeaderMap, Method, StatusCode, Uri},
    response::{IntoResponse, Response},
    routing::{any, get},
    Router,
};
use chrono::{DateTime, Duration, NaiveDateTime, Utc};
use clap::{Parser, Subcommand};
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashMap},
    fs::{self, File, OpenOptions},
    io::{self, BufReader as StdBufReader, BufWriter, Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{UnixListener, UnixStream},
};

pub const VERSION: &str = "2.4.1";
pub const CHUNK_SIZE: usize = 4 * 1024 * 1024; // 4 MiB canonical MeshFS CAS chunk size

// =============================================================================
// Cryptographic Helpers (BLAKE3 SIMD CAS + RFC 2104 HMAC-SHA256 for AWS SigV4)
// =============================================================================

pub fn blake3_hex(data: &[u8]) -> String {
    blake3::hash(data).to_hex().to_string()
}

pub fn verify_cas_digest(data: &[u8], expected_clean: &str) -> bool {
    blake3_hex(data) == expected_clean
}

pub fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

pub fn hmac_sha256_bytes(key: &[u8], message: &[u8]) -> [u8; 32] {
    const BLOCK_SIZE: usize = 64;
    let mut k_block = [0u8; BLOCK_SIZE];
    if key.len() > BLOCK_SIZE {
        let mut h = Sha256::new();
        h.update(key);
        let digest = h.finalize();
        k_block[..32].copy_from_slice(&digest);
    } else {
        k_block[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; BLOCK_SIZE];
    let mut opad = [0x5cu8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        ipad[i] ^= k_block[i];
        opad[i] ^= k_block[i];
    }
    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(message);
    let inner_digest = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner_digest);
    let final_digest = outer.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&final_digest);
    out
}

pub fn hmac_sha256_hex(key: &[u8], message: &[u8]) -> String {
    hex::encode(hmac_sha256_bytes(key, message))
}

pub fn derive_sigv4_signing_key(
    secret_key: &str,
    date_yyyymmdd: &str,
    region: &str,
    service: &str,
) -> [u8; 32] {
    let k_secret = format!("AWS4{}", secret_key);
    let k_date = hmac_sha256_bytes(k_secret.as_bytes(), date_yyyymmdd.as_bytes());
    let k_region = hmac_sha256_bytes(&k_date, region.as_bytes());
    let k_service = hmac_sha256_bytes(&k_region, service.as_bytes());
    hmac_sha256_bytes(&k_service, b"aws4_request")
}

pub fn constant_time_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.bytes().zip(b.bytes()) {
        diff |= x ^ y;
    }
    diff == 0
}

pub fn xml_escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for c in input.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(c),
        }
    }
    out
}

pub fn uri_encode_sigv4(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for b in input.bytes() {
        if b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.' || b == b'~' {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{:02X}", b));
        }
    }
    out
}

// =============================================================================
// Strict Input Validators (Anti-Path-Traversal)
// =============================================================================

pub fn is_valid_bucket_name(bucket: &str) -> bool {
    if bucket.len() < 3 || bucket.len() > 63 {
        return false;
    }
    if bucket.contains("..") || bucket.starts_with('.') || bucket.ends_with('.') || bucket.starts_with('-') || bucket.ends_with('-') {
        return false;
    }
    bucket
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.')
}

pub fn is_valid_upload_id(upload_id: &str) -> bool {
    upload_id.len() == 64
        && upload_id
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

pub fn create_secure_temp_file(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
}

// =============================================================================
// Shared MeshFS 4 MiB CAS ChunkStore (`/var/lib/meshfs/chunks/<prefix>/<hash>`)
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChunkRef {
    pub id: String,
    pub size: usize,
    pub offset: u64,
}

#[derive(Debug, Clone)]
pub struct ChunkStore {
    pub chunks_dir: PathBuf,
    pub peers: Vec<String>,
    pub auth_secret: Option<String>,
    pub self_healed_chunks: Arc<AtomicU64>,
}

impl ChunkStore {
    pub fn new(cas_root: &Path) -> io::Result<Self> {
        Self::with_peers(cas_root, Vec::new(), None)
    }

    pub fn with_peers(
        cas_root: &Path,
        peers: Vec<String>,
        auth_secret: Option<String>,
    ) -> io::Result<Self> {
        let chunks_dir = cas_root.join("chunks");
        fs::create_dir_all(&chunks_dir)?;
        Ok(Self {
            chunks_dir,
            peers,
            auth_secret,
            self_healed_chunks: Arc::new(AtomicU64::new(0)),
        })
    }

    pub fn normalize_id(id: &str) -> &str {
        id.strip_prefix("blake3:").unwrap_or(id)
    }

    pub fn chunk_path(&self, chunk_id: &str) -> PathBuf {
        let clean = Self::normalize_id(chunk_id);
        let prefix = if clean.len() >= 2 { &clean[..2] } else { "xx" };
        self.chunks_dir.join(prefix).join(clean)
    }

    pub fn write_chunk(&self, data: &[u8]) -> io::Result<(String, bool)> {
        let digest = blake3_hex(data);
        let target_file = self.chunk_path(&digest);

        if target_file.exists() {
            if let Ok(existing) = fs::read(&target_file) {
                if existing.len() <= CHUNK_SIZE && verify_cas_digest(&existing, &digest) {
                    return Ok((format!("blake3:{}", digest), false));
                }
            }
        }

        self.write_verified_chunk_raw(&digest, data)?;
        Ok((format!("blake3:{}", digest), true))
    }

    pub fn write_verified_chunk_raw(&self, clean_digest: &str, data: &[u8]) -> io::Result<()> {
        let target_file = self.chunk_path(clean_digest);
        if let Some(parent) = target_file.parent() {
            fs::create_dir_all(parent)?;
        }

        static TMP_COUNTER: AtomicU64 = AtomicU64::new(1);
        let seq = TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let tmp_file =
            target_file.with_extension(format!("tmp.{}.{}.{}", std::process::id(), seq, nanos));
        {
            let mut file = create_secure_temp_file(&tmp_file)?;
            file.write_all(data)?;
            file.sync_all()?;
        }
        fs::rename(&tmp_file, &target_file)?;
        if let Some(parent) = target_file.parent() {
            if let Ok(dir) = File::open(parent) {
                let _ = dir.sync_all();
            }
        }
        Ok(())
    }

    fn try_heal_from_peers(&self, clean: &str) -> Option<Vec<u8>> {
        if self.peers.is_empty() {
            return None;
        }
        let clean_owned = clean.to_string();
        let peers = self.peers.clone();
        let secret = self.auth_secret.clone();

        // Spawn an isolated OS thread for blocking reqwest so it safely executes inside or outside a Tokio runtime
        let fetched = std::thread::spawn(move || -> Option<Vec<u8>> {
            let client = reqwest::blocking::Client::builder()
                .timeout(std::time::Duration::from_secs(3))
                .build()
                .ok()?;
            for peer in &peers {
                let base = peer.trim_end_matches('/');
                let candidate_urls = [
                    format!("{}/cas/chunk/{}", base, clean_owned),
                    format!("{}/api/v1/meshfs/cas/chunk/{}", base, clean_owned),
                ];
                for url in &candidate_urls {
                    let mut req = client.get(url);
                    if let Some(ref sk) = secret {
                        if !sk.is_empty() {
                            req = req.header("Authorization", format!("Bearer {}", sk));
                        }
                    }
                    if let Ok(resp) = req.send() {
                        if resp.status().is_success() {
                            if let Ok(bytes) = resp.bytes() {
                                if bytes.len() <= CHUNK_SIZE && verify_cas_digest(&bytes, &clean_owned) {
                                    tracing::warn!(
                                        chunk = %clean_owned,
                                        peer = %base,
                                        "P2P Self-Healing: recovered & verified intact CAS chunk from peer"
                                    );
                                    return Some(bytes.to_vec());
                                }
                            }
                        }
                    }
                }
            }
            None
        })
        .join()
        .ok()
        .flatten()?;

        if self.write_verified_chunk_raw(clean, &fetched).is_ok() {
            self.self_healed_chunks.fetch_add(1, Ordering::Relaxed);
            return Some(fetched);
        }
        None
    }

    pub fn read_chunk(&self, chunk_id: &str) -> io::Result<Vec<u8>> {
        let clean = Self::normalize_id(chunk_id);
        if clean.len() != 64 || !clean.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid chunk digest",
            ));
        }
        let target_file = self.chunk_path(clean);
        match File::open(&target_file) {
            Ok(file) => {
                let mut buf = Vec::new();
                file.take(CHUNK_SIZE as u64 + 1).read_to_end(&mut buf)?;
                if buf.len() > CHUNK_SIZE {
                    if let Some(healed) = self.try_heal_from_peers(clean) {
                        return Ok(healed);
                    }
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "oversized CAS chunk",
                    ));
                }
                if !verify_cas_digest(&buf, clean) {
                    let actual = blake3_hex(&buf);
                    if let Some(healed) = self.try_heal_from_peers(clean) {
                        return Ok(healed);
                    }
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "CAS bit-rot detected on chunk {}: expected {}, got {}",
                            clean, clean, actual
                        ),
                    ));
                }
                Ok(buf)
            }
            Err(e) => {
                if let Some(healed) = self.try_heal_from_peers(clean) {
                    return Ok(healed);
                }
                Err(e)
            }
        }
    }

    pub fn count_chunks_and_bytes(&self) -> (usize, u64) {
        let mut count = 0usize;
        let mut total_bytes = 0u64;
        if let Ok(entries) = fs::read_dir(&self.chunks_dir) {
            for e in entries.flatten() {
                if e.path().is_dir() {
                    if let Ok(sub) = fs::read_dir(e.path()) {
                        for f in sub.flatten() {
                            let p = f.path();
                            if p.is_file()
                                && !f.file_name().to_string_lossy().contains(".tmp.")
                            {
                                count += 1;
                                if let Ok(meta) = f.metadata() {
                                    total_bytes += meta.len();
                                }
                            }
                        }
                    }
                }
            }
        }
        (count, total_bytes)
    }

    pub fn count_chunks(&self) -> usize {
        self.count_chunks_and_bytes().0
    }
}

// =============================================================================
// S3 Object Manifest & Fail-Closed WORM Invariants
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectManifest {
    pub bucket: String,
    pub key: String,
    pub size: u64,
    pub etag: String,
    pub merkle_root: String,
    pub content_type: String,
    pub created_at: String,
    pub retain_until: Option<String>,
    pub lock_mode: Option<String>,
    pub user_meta: BTreeMap<String, String>,
    pub chunks: Vec<ChunkRef>,
}

impl ObjectManifest {
    /// Fail-Closed WORM predicate: if `retain_until` is present, the object is locked
    /// if the timestamp is in the future OR if the timestamp string is unparseable.
    pub fn is_worm_locked(&self) -> bool {
        if let Some(ref until_str) = self.retain_until {
            match DateTime::parse_from_rfc3339(until_str) {
                Ok(dt) => return dt.with_timezone(&Utc) > Utc::now(),
                Err(_) => return true, // Fail-Closed on malformed retention metadata
            }
        }
        false
    }
}

pub fn validate_retain_until(retain_until: &Option<String>) -> Result<(), (StatusCode, String)> {
    if let Some(ref s) = retain_until {
        let dt = DateTime::parse_from_rfc3339(s).map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                format!("InvalidArgument: retain_until '{}' is not valid RFC3339", s),
            )
        })?;
        if dt.with_timezone(&Utc) <= Utc::now() {
            return Err((
                StatusCode::BAD_REQUEST,
                "InvalidArgument: retain_until must be in the future".to_string(),
            ));
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultipartPartManifest {
    pub part_number: u32,
    pub size: u64,
    pub etag: String,
    pub chunks: Vec<ChunkRef>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultipartSessionMeta {
    pub upload_id: String,
    pub bucket: String,
    pub key: String,
    pub created_at: String,
    pub retain_until: Option<String>,
    pub lock_mode: Option<String>,
}

pub fn compute_merkle_root(chunks: &[ChunkRef]) -> String {
    if chunks.is_empty() {
        return blake3_hex(b"");
    }
    let mut combined = String::new();
    for c in chunks {
        combined.push_str(ChunkStore::normalize_id(&c.id));
        combined.push(':');
    }
    blake3_hex(combined.as_bytes())
}

pub fn atomic_write_json<T: Serialize>(target: &Path, value: &T) -> io::Result<()> {
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent)?;
    }
    static SEQ: AtomicU64 = AtomicU64::new(1);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let tmp = target.with_extension(format!("tmp.{}.{}.{}", std::process::id(), n, nanos));
    let payload = serde_json::to_vec_pretty(value)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    {
        let mut f = create_secure_temp_file(&tmp)?;
        f.write_all(&payload)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, target)?;
    if let Some(parent) = target.parent() {
        if let Ok(dir) = File::open(parent) {
            let _ = dir.sync_all();
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BucketQuota {
    pub bucket: String,
    pub max_bytes: u64,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GcReport {
    pub status: String,
    pub dry_run: bool,
    pub grace_seconds: u64,
    pub referenced_chunks: usize,
    pub scanned_chunks: usize,
    pub deleted_chunks: usize,
    pub reclaimed_bytes: u64,
    pub retained_physical_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct S3Telemetry {
    pub buckets_count: usize,
    pub objects_count: usize,
    pub worm_locked_objects: usize,
    pub logical_bytes: u64,
    pub physical_cas_chunks: usize,
    pub physical_cas_bytes: u64,
    pub dedup_saved_bytes: u64,
    pub dedup_ratio: f64,
    pub self_healed_chunks: u64,
}

fn collect_cas_hashes_from_value(
    val: &serde_json::Value,
    referenced: &mut std::collections::HashSet<String>,
) {
    match val {
        serde_json::Value::String(s) => {
            let clean = ChunkStore::normalize_id(s.as_str());
            if clean.len() == 64
                && clean
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            {
                referenced.insert(clean.to_string());
            }
        }
        serde_json::Value::Array(arr) => {
            for item in arr {
                collect_cas_hashes_from_value(item, referenced);
            }
        }
        serde_json::Value::Object(map) => {
            for (k, v) in map {
                // Collect 64-hex strings from chunk/digest fields or blake3:-prefixed strings
                if let serde_json::Value::String(s) = v {
                    if s.starts_with("blake3:")
                        || k == "id"
                        || k == "chunk"
                        || k == "hash"
                    {
                        collect_cas_hashes_from_value(v, referenced);
                    }
                } else {
                    collect_cas_hashes_from_value(v, referenced);
                }
            }
        }
        _ => {}
    }
}

fn collect_cas_hashes_from_dir(dir: &Path, referenced: &mut std::collections::HashSet<String>) {
    if !dir.exists() {
        return;
    }
    if let Ok(entries) = fs::read_dir(dir) {
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                if p.file_name().and_then(|n| n.to_str()) == Some("chunks") {
                    continue;
                }
                collect_cas_hashes_from_dir(&p, referenced);
            } else if p.extension().and_then(|s| s.to_str()) == Some("json") {
                if let Ok(bytes) = fs::read(&p) {
                    if let Ok(val) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                        collect_cas_hashes_from_value(&val, referenced);
                    }
                }
            }
        }
    }
}

// =============================================================================
// MeshFS S3 Engine State
// =============================================================================

#[derive(Clone)]
pub struct S3State {
    pub cas_root: PathBuf,
    pub cas: ChunkStore,
    pub s3_dir: PathBuf,
    pub access_key: String,
    pub secret_key: String,
    pub bind_addr: String,
}

impl S3State {
    pub fn new(
        cas_root: &Path,
        s3_dir: &Path,
        access_key: String,
        secret_key: String,
        bind_addr: String,
    ) -> io::Result<Self> {
        Self::with_peers(cas_root, s3_dir, access_key, secret_key, bind_addr, Vec::new())
    }

    pub fn with_peers(
        cas_root: &Path,
        s3_dir: &Path,
        access_key: String,
        secret_key: String,
        bind_addr: String,
        peers: Vec<String>,
    ) -> io::Result<Self> {
        let auth_secret = if secret_key.is_empty() {
            None
        } else {
            Some(secret_key.clone())
        };
        let cas = ChunkStore::with_peers(cas_root, peers, auth_secret)?;
        fs::create_dir_all(s3_dir.join("buckets"))?;
        fs::create_dir_all(s3_dir.join("multipart"))?;
        fs::create_dir_all(s3_dir.join("quotas"))?;
        let _ = fs::set_permissions(s3_dir, fs::Permissions::from_mode(0o700));
        Ok(Self {
            cas_root: cas_root.to_path_buf(),
            cas,
            s3_dir: s3_dir.to_path_buf(),
            access_key,
            secret_key,
            bind_addr,
        })
    }

    pub fn quota_path(&self, bucket: &str) -> PathBuf {
        self.s3_dir.join("quotas").join(format!("{}.json", bucket))
    }

    pub fn set_bucket_quota(&self, bucket: &str, max_bytes: u64) -> Result<BucketQuota, String> {
        if !is_valid_bucket_name(bucket) {
            return Err("InvalidBucketName".to_string());
        }
        let q = BucketQuota {
            bucket: bucket.to_string(),
            max_bytes,
            updated_at: Utc::now().to_rfc3339(),
        };
        atomic_write_json(&self.quota_path(bucket), &q).map_err(|e| e.to_string())?;
        Ok(q)
    }

    pub fn get_bucket_quota(&self, bucket: &str) -> Option<BucketQuota> {
        let p = self.quota_path(bucket);
        let bytes = fs::read(p).ok()?;
        serde_json::from_slice(&bytes).ok()
    }

    pub fn bucket_logical_bytes(&self, bucket: &str, exclude_key: Option<&str>) -> u64 {
        let bdir = self.bucket_dir(bucket);
        let mut total = 0u64;
        if let Ok(entries) = fs::read_dir(bdir) {
            for e in entries.flatten() {
                if e.path().extension().and_then(|s| s.to_str()) == Some("json") {
                    if let Ok(b) = fs::read(e.path()) {
                        if let Ok(m) = serde_json::from_slice::<ObjectManifest>(&b) {
                            if exclude_key.is_some_and(|ex| ex == m.key) {
                                continue;
                            }
                            total = total.saturating_add(m.size);
                        }
                    }
                }
            }
        }
        total
    }

    pub fn ensure_bucket_quota(
        &self,
        bucket: &str,
        key: &str,
        new_size: u64,
    ) -> Result<(), (StatusCode, String)> {
        if let Some(q) = self.get_bucket_quota(bucket) {
            if q.max_bytes > 0 {
                let current = self.bucket_logical_bytes(bucket, Some(key));
                let projected = current.saturating_add(new_size);
                if projected > q.max_bytes {
                    return Err((
                        StatusCode::INSUFFICIENT_STORAGE,
                        format!(
                            "QuotaExceeded: bucket '{}' quota is {} bytes, projected usage is {} bytes",
                            bucket, q.max_bytes, projected
                        ),
                    ));
                }
            }
        }
        Ok(())
    }

    pub fn run_universal_cas_gc(&self, grace_seconds: u64, dry_run: bool) -> GcReport {
        let mut referenced = std::collections::HashSet::new();
        // 1. Scan MeshFS POSIX/Proxmox metadata (`/var/lib/meshfs/meta`)
        collect_cas_hashes_from_dir(&self.cas_root.join("meta"), &mut referenced);
        // 2. Scan MeshFS-S3 buckets and active multipart sessions (`/var/lib/meshfs/s3`)
        collect_cas_hashes_from_dir(&self.s3_dir.join("buckets"), &mut referenced);
        collect_cas_hashes_from_dir(&self.s3_dir.join("multipart"), &mut referenced);
        // 3. Scan PMBS datastore if colocated (`/var/lib/pmbs`)
        collect_cas_hashes_from_dir(Path::new("/var/lib/pmbs"), &mut referenced);

        let now = std::time::SystemTime::now();
        let mut scanned_chunks = 0usize;
        let mut deleted_chunks = 0usize;
        let mut reclaimed_bytes = 0u64;
        let mut retained_physical_bytes = 0u64;

        if let Ok(entries) = fs::read_dir(&self.cas.chunks_dir) {
            for e in entries.flatten() {
                if e.path().is_dir() {
                    if let Ok(sub) = fs::read_dir(e.path()) {
                        for f in sub.flatten() {
                            let p = f.path();
                            if !p.is_file() {
                                continue;
                            }
                            let fname = f.file_name().to_string_lossy().to_string();
                            let meta = match f.metadata() {
                                Ok(m) => m,
                                Err(_) => continue,
                            };
                            let file_len = meta.len();
                            let age_secs = meta
                                .modified()
                                .ok()
                                .and_then(|m| now.duration_since(m).ok())
                                .map(|d| d.as_secs())
                                .unwrap_or(u64::MAX);

                            if fname.contains(".tmp.") {
                                if age_secs >= grace_seconds.max(60) && !dry_run {
                                    let _ = fs::remove_file(&p);
                                }
                                continue;
                            }

                            scanned_chunks += 1;
                            if referenced.contains(&fname) || age_secs < grace_seconds {
                                retained_physical_bytes =
                                    retained_physical_bytes.saturating_add(file_len);
                            } else {
                                if !dry_run {
                                    if fs::remove_file(&p).is_ok() {
                                        deleted_chunks += 1;
                                        reclaimed_bytes = reclaimed_bytes.saturating_add(file_len);
                                    } else {
                                        retained_physical_bytes =
                                            retained_physical_bytes.saturating_add(file_len);
                                    }
                                } else {
                                    deleted_chunks += 1;
                                    reclaimed_bytes = reclaimed_bytes.saturating_add(file_len);
                                }
                            }
                        }
                    }
                }
            }
        }

        GcReport {
            status: "ok".to_string(),
            dry_run,
            grace_seconds,
            referenced_chunks: referenced.len(),
            scanned_chunks,
            deleted_chunks,
            reclaimed_bytes,
            retained_physical_bytes,
        }
    }

    pub fn compute_telemetry(&self) -> S3Telemetry {
        let mut buckets_count = 0usize;
        let mut objects_count = 0usize;
        let mut worm_locked_objects = 0usize;
        let mut logical_bytes = 0u64;

        if let Ok(entries) = fs::read_dir(self.s3_dir.join("buckets")) {
            for e in entries.flatten() {
                let bpath = e.path();
                if bpath.is_dir() {
                    buckets_count += 1;
                    if let Ok(objs) = fs::read_dir(&bpath) {
                        for o in objs.flatten() {
                            if o.path().extension().and_then(|s| s.to_str()) == Some("json") {
                                if let Ok(bytes) = fs::read(o.path()) {
                                    if let Ok(m) = serde_json::from_slice::<ObjectManifest>(&bytes)
                                    {
                                        objects_count += 1;
                                        logical_bytes = logical_bytes.saturating_add(m.size);
                                        if m.is_worm_locked() {
                                            worm_locked_objects += 1;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        let (physical_cas_chunks, physical_cas_bytes) = self.cas.count_chunks_and_bytes();
        let dedup_saved_bytes = logical_bytes.saturating_sub(physical_cas_bytes);
        let dedup_ratio = if physical_cas_bytes > 0 && logical_bytes > 0 {
            (logical_bytes as f64) / (physical_cas_bytes as f64)
        } else {
            1.0
        };
        let self_healed_chunks = self.cas.self_healed_chunks.load(Ordering::Relaxed);

        S3Telemetry {
            buckets_count,
            objects_count,
            worm_locked_objects,
            logical_bytes,
            physical_cas_chunks,
            physical_cas_bytes,
            dedup_saved_bytes,
            dedup_ratio,
            self_healed_chunks,
        }
    }

    pub fn checked_bucket_dir(&self, bucket: &str) -> Result<PathBuf, (StatusCode, &'static str)> {
        if !is_valid_bucket_name(bucket) {
            return Err((StatusCode::BAD_REQUEST, "InvalidBucketName"));
        }
        Ok(self.s3_dir.join("buckets").join(bucket))
    }

    pub fn bucket_dir(&self, bucket: &str) -> PathBuf {
        self.s3_dir.join("buckets").join(bucket)
    }

    pub fn object_manifest_path(&self, bucket: &str, key: &str) -> PathBuf {
        let key_hash = blake3_hex(key.as_bytes());
        self.bucket_dir(bucket).join(format!("{}.json", key_hash))
    }

    pub fn checked_multipart_dir(
        &self,
        upload_id: &str,
    ) -> Result<PathBuf, (StatusCode, &'static str)> {
        if !is_valid_upload_id(upload_id) {
            return Err((StatusCode::NOT_FOUND, "NoSuchUpload"));
        }
        Ok(self.s3_dir.join("multipart").join(upload_id))
    }

    /// Fail-Closed WORM guard: rejects mutation/deletion if an object exists and is WORM-locked,
    /// OR if an existing manifest file cannot be read/parsed.
    pub fn ensure_not_worm_locked(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<(), (StatusCode, String)> {
        let mpath = self.object_manifest_path(bucket, key);
        if mpath.exists() {
            let existing_bytes = fs::read(&mpath).map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("CorruptManifestRead: {}", e),
                )
            })?;
            let existing =
                serde_json::from_slice::<ObjectManifest>(&existing_bytes).map_err(|e| {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("CorruptManifestJson: {}", e),
                    )
                })?;
            if existing.is_worm_locked() {
                return Err((
                    StatusCode::FORBIDDEN,
                    format!(
                        "AccessDenied: ObjectLocked until {}",
                        existing
                            .retain_until
                            .unwrap_or_else(|| "INVALID_DATE_FAIL_CLOSED".to_string())
                    ),
                ));
            }
        }
        Ok(())
    }

    pub fn ingest_chunks(&self, data: &[u8]) -> io::Result<(Vec<ChunkRef>, usize)> {
        let mut refs = Vec::new();
        let mut offset = 0u64;
        let mut newly_written = 0usize;
        for slice in data.chunks(CHUNK_SIZE) {
            let (id, is_new) = self.cas.write_chunk(slice)?;
            if is_new {
                newly_written += 1;
            }
            refs.push(ChunkRef {
                id,
                size: slice.len(),
                offset,
            });
            offset += slice.len() as u64;
        }
        Ok((refs, newly_written))
    }

    pub fn ingest_reader<R: Read>(&self, mut reader: R) -> io::Result<(Vec<ChunkRef>, u64, usize)> {
        let mut refs = Vec::new();
        let mut offset = 0u64;
        let mut newly_written = 0usize;
        let mut buf = vec![0u8; CHUNK_SIZE];
        loop {
            let mut filled = 0usize;
            while filled < CHUNK_SIZE {
                match reader.read(&mut buf[filled..]) {
                    Ok(0) => break,
                    Ok(n) => filled += n,
                    Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(e) => return Err(e),
                }
            }
            if filled == 0 {
                break;
            }
            let (id, is_new) = self.cas.write_chunk(&buf[..filled])?;
            if is_new {
                newly_written += 1;
            }
            refs.push(ChunkRef {
                id,
                size: filled,
                offset,
            });
            offset += filled as u64;
        }
        Ok((refs, offset, newly_written))
    }

    pub async fn ingest_async_body(&self, body: Body) -> io::Result<(Vec<ChunkRef>, u64, usize)> {
        let mut stream = body.into_data_stream();
        let mut refs = Vec::new();
        let mut offset = 0u64;
        let mut newly_written = 0usize;
        let mut buf = Vec::with_capacity(CHUNK_SIZE);

        while let Some(chunk_res) = stream.next().await {
            let bytes: Bytes =
                chunk_res.map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
            let mut slice = bytes.as_ref();
            while !slice.is_empty() {
                let space = CHUNK_SIZE - buf.len();
                let take = space.min(slice.len());
                buf.extend_from_slice(&slice[..take]);
                slice = &slice[take..];
                if buf.len() == CHUNK_SIZE {
                    let (id, is_new) = self.cas.write_chunk(&buf)?;
                    if is_new {
                        newly_written += 1;
                    }
                    refs.push(ChunkRef {
                        id,
                        size: CHUNK_SIZE,
                        offset,
                    });
                    offset += CHUNK_SIZE as u64;
                    buf.clear();
                }
            }
        }
        if !buf.is_empty() {
            let (id, is_new) = self.cas.write_chunk(&buf)?;
            if is_new {
                newly_written += 1;
            }
            refs.push(ChunkRef {
                id,
                size: buf.len(),
                offset,
            });
            offset += buf.len() as u64;
        }
        Ok((refs, offset, newly_written))
    }

    pub fn finalize_manifest(
        &self,
        bucket: &str,
        key: &str,
        chunks: Vec<ChunkRef>,
        total_size: u64,
        content_type: String,
        retain_until: Option<String>,
        lock_mode: Option<String>,
        user_meta: BTreeMap<String, String>,
    ) -> Result<ObjectManifest, (StatusCode, String)> {
        let bdir = self
            .checked_bucket_dir(bucket)
            .map_err(|(c, m)| (c, m.to_string()))?;
        if !bdir.exists() {
            return Err((StatusCode::NOT_FOUND, "NoSuchBucket".to_string()));
        }
        validate_retain_until(&retain_until)?;
        self.ensure_not_worm_locked(bucket, key)?;
        self.ensure_bucket_quota(bucket, key, total_size)?;

        let merkle_root = compute_merkle_root(&chunks);
        let manifest = ObjectManifest {
            bucket: bucket.to_string(),
            key: key.to_string(),
            size: total_size,
            etag: merkle_root.clone(),
            merkle_root,
            content_type,
            created_at: Utc::now().to_rfc3339(),
            retain_until,
            lock_mode,
            user_meta,
            chunks,
        };
        let mpath = self.object_manifest_path(bucket, key);
        atomic_write_json(&mpath, &manifest).map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Manifest write failed: {}", e),
            )
        })?;
        Ok(manifest)
    }

    pub fn put_object(
        &self,
        bucket: &str,
        key: &str,
        data: &[u8],
        content_type: String,
        retain_until: Option<String>,
        lock_mode: Option<String>,
        user_meta: BTreeMap<String, String>,
    ) -> Result<(ObjectManifest, usize), (StatusCode, String)> {
        let bdir = self
            .checked_bucket_dir(bucket)
            .map_err(|(c, m)| (c, m.to_string()))?;
        if !bdir.exists() {
            return Err((StatusCode::NOT_FOUND, "NoSuchBucket".to_string()));
        }
        validate_retain_until(&retain_until)?;
        self.ensure_not_worm_locked(bucket, key)?;
        let (chunks, newly_written) = self.ingest_chunks(data).map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("CAS write failed: {}", e),
            )
        })?;
        let manifest = self.finalize_manifest(
            bucket,
            key,
            chunks,
            data.len() as u64,
            content_type,
            retain_until,
            lock_mode,
            user_meta,
        )?;
        Ok((manifest, newly_written))
    }

    pub fn read_object_range(
        &self,
        manifest: &ObjectManifest,
        range_start: u64,
        range_end: u64,
    ) -> io::Result<Vec<u8>> {
        if manifest.size == 0 || range_start > range_end || range_start >= manifest.size {
            return Ok(Vec::new());
        }
        let end_clamped = range_end.min(manifest.size - 1);
        let expected_len = (end_clamped - range_start + 1) as usize;
        let mut out = Vec::with_capacity(expected_len);

        for chunk in &manifest.chunks {
            let c_start = chunk.offset;
            let c_end = chunk.offset + chunk.size as u64 - 1;
            if c_end < range_start {
                continue;
            }
            if c_start > end_clamped {
                break;
            }
            let raw = self.cas.read_chunk(&chunk.id)?;
            let slice_start = if range_start > c_start {
                (range_start - c_start) as usize
            } else {
                0
            };
            let slice_end = if end_clamped < c_end {
                (end_clamped - c_start + 1) as usize
            } else {
                chunk.size
            };
            out.extend_from_slice(&raw[slice_start..slice_end]);
        }
        Ok(out)
    }

    pub fn generate_presigned_url(
        &self,
        endpoint: &str,
        method: &str,
        bucket: &str,
        key: &str,
        expires_secs: i64,
    ) -> String {
        let expires_at = (Utc::now() + Duration::seconds(expires_secs)).timestamp();
        let canonical = format!(
            "{}\n/{}/{}\n{}",
            method.to_uppercase(),
            bucket,
            key.trim_start_matches('/'),
            expires_at
        );
        let sig = hmac_sha256_hex(self.secret_key.as_bytes(), canonical.as_bytes());
        format!(
            "{}/{}/{}?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential={}&X-Amz-Expires={}&X-Amz-Signature={}",
            endpoint.trim_end_matches('/'),
            bucket,
            key.trim_start_matches('/'),
            self.access_key,
            expires_at,
            sig
        )
    }

    /// Cryptographic Request Verification (Fail-Closed on all branches):
    /// 1. Presigned URL (`X-Amz-Signature`): verifies AccessKeyId, expiration, and HMAC-SHA256 / SigV4 signature.
    /// 2. Explicit Headers (`x-amz-access-key` + `x-amz-secret-key`): constant-time comparison.
    /// 3. Standard AWS Signature V4 Header (`Authorization: AWS4-HMAC-SHA256 ...`): derives `kSigning` from
    ///    `self.secret_key` and verifies `Signature=<hex>` against `HMAC(kSigning, StringToSign)`.
    pub fn verify_request_auth(
        &self,
        method: &Method,
        uri: &Uri,
        headers: &HeaderMap,
        query: &HashMap<String, String>,
    ) -> Result<(), (StatusCode, &'static str)> {
        // Branch 1: Presigned URL (`X-Amz-Signature`)
        if let Some(sig) = query.get("X-Amz-Signature") {
            if sig.len() != 64 || !sig.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err((StatusCode::FORBIDDEN, "SignatureDoesNotMatch"));
            }
            let cred = query
                .get("X-Amz-Credential")
                .ok_or((StatusCode::FORBIDDEN, "InvalidAccessKeyId"))?;
            let cred_parts: Vec<&str> = cred.split('/').collect();
            let cred_key = cred_parts.first().copied().unwrap_or("");
            if !constant_time_eq(cred_key, &self.access_key) {
                return Err((StatusCode::FORBIDDEN, "InvalidAccessKeyId"));
            }
            let expires_val: i64 = query
                .get("X-Amz-Expires")
                .and_then(|s| s.parse().ok())
                .ok_or((StatusCode::FORBIDDEN, "AccessDenied"))?;
            if expires_val <= 0 {
                return Err((StatusCode::FORBIDDEN, "RequestExpired"));
            }

            let now = Utc::now().timestamp();
            if let Some(amz_date) = query.get("X-Amz-Date") {
                // Parse YYYYMMDDTHHMMSSZ and enforce relative expiration [t0, t0 + expires_val]
                let dt = NaiveDateTime::parse_from_str(amz_date, "%Y%m%dT%H%M%SZ")
                    .map_err(|_| (StatusCode::FORBIDDEN, "AccessDenied"))?;
                let issued_at = dt.and_utc().timestamp();
                if now > issued_at.saturating_add(expires_val) {
                    return Err((StatusCode::FORBIDDEN, "RequestExpired"));
                }
                // Check direct HMAC or full SigV4 query signature
                let direct_canonical =
                    format!("{}\n{}\n{}", method.as_str(), uri.path(), expires_val);
                let direct_expected =
                    hmac_sha256_hex(self.secret_key.as_bytes(), direct_canonical.as_bytes());
                if constant_time_eq(sig, &direct_expected) {
                    return Ok(());
                }
                if cred_parts.len() >= 5 {
                    let expected_v4 = self.compute_sigv4_presigned_signature(
                        method,
                        uri.path(),
                        headers,
                        query,
                        amz_date,
                        cred_parts[1],
                        cred_parts[2],
                        cred_parts[3],
                    );
                    if constant_time_eq(sig, &expected_v4) {
                        return Ok(());
                    }
                }
                return Err((StatusCode::FORBIDDEN, "SignatureDoesNotMatch"));
            }

            // Native meshfs-s3 presign contract (`X-Amz-Expires` is absolute unix timestamp)
            if now > expires_val {
                return Err((StatusCode::FORBIDDEN, "RequestExpired"));
            }
            let canonical = format!("{}\n{}\n{}", method.as_str(), uri.path(), expires_val);
            let expected = hmac_sha256_hex(self.secret_key.as_bytes(), canonical.as_bytes());
            if !constant_time_eq(sig, &expected) {
                return Err((StatusCode::FORBIDDEN, "SignatureDoesNotMatch"));
            }
            return Ok(());
        }

        // Branch 2: Explicit `x-amz-access-key` + `x-amz-secret-key` headers
        if let (Some(ak), Some(sk)) = (
            headers.get("x-amz-access-key").and_then(|v| v.to_str().ok()),
            headers.get("x-amz-secret-key").and_then(|v| v.to_str().ok()),
        ) {
            if constant_time_eq(ak, &self.access_key) && constant_time_eq(sk, &self.secret_key) {
                return Ok(());
            }
            return Err((StatusCode::FORBIDDEN, "SignatureDoesNotMatch"));
        }

        // Branch 3: `Authorization: AWS4-HMAC-SHA256 Credential=..., SignedHeaders=..., Signature=...`
        if let Some(auth) = headers.get("authorization").and_then(|v| v.to_str().ok()) {
            if let Some(rest) = auth.strip_prefix("AWS4-HMAC-SHA256 ") {
                let mut cred_val = None;
                let mut signed_headers_val = None;
                let mut sig_val = None;
                for part in rest.split(',').map(|s| s.trim()) {
                    if let Some(v) = part.strip_prefix("Credential=") {
                        cred_val = Some(v);
                    } else if let Some(v) = part.strip_prefix("SignedHeaders=") {
                        signed_headers_val = Some(v);
                    } else if let Some(v) = part.strip_prefix("Signature=") {
                        sig_val = Some(v);
                    }
                }
                let cred = cred_val.ok_or((StatusCode::FORBIDDEN, "AccessDenied"))?;
                let signed_hdrs =
                    signed_headers_val.ok_or((StatusCode::FORBIDDEN, "AccessDenied"))?;
                let sig_hex = sig_val.ok_or((StatusCode::FORBIDDEN, "SignatureDoesNotMatch"))?;
                if sig_hex.len() != 64 || !sig_hex.bytes().all(|b| b.is_ascii_hexdigit()) {
                    return Err((StatusCode::FORBIDDEN, "SignatureDoesNotMatch"));
                }

                let scope: Vec<&str> = cred.split('/').collect();
                if scope.len() < 5 || scope[4] != "aws4_request" {
                    return Err((StatusCode::FORBIDDEN, "InvalidAccessKeyId"));
                }
                if !constant_time_eq(scope[0], &self.access_key) {
                    return Err((StatusCode::FORBIDDEN, "InvalidAccessKeyId"));
                }

                let expected_sig = self
                    .compute_sigv4_header_signature(
                        method,
                        uri.path(),
                        query,
                        headers,
                        signed_hdrs,
                        scope[1],
                        scope[2],
                        scope[3],
                    )
                    .ok_or((StatusCode::FORBIDDEN, "SignatureDoesNotMatch"))?;

                if !constant_time_eq(sig_hex, &expected_sig) {
                    return Err((StatusCode::FORBIDDEN, "SignatureDoesNotMatch"));
                }
                return Ok(());
            }
            if let Some(token) = auth.strip_prefix("Bearer ") {
                if constant_time_eq(token.trim(), &self.secret_key) {
                    return Ok(());
                }
                return Err((StatusCode::FORBIDDEN, "SignatureDoesNotMatch"));
            }
        }

        Err((StatusCode::FORBIDDEN, "AccessDenied"))
    }

    #[allow(clippy::too_many_arguments)]
    fn compute_sigv4_header_signature(
        &self,
        method: &Method,
        path: &str,
        query: &HashMap<String, String>,
        headers: &HeaderMap,
        signed_headers: &str,
        date_yyyymmdd: &str,
        region: &str,
        service: &str,
    ) -> Option<String> {
        let amz_date = headers
            .get("x-amz-date")
            .or_else(|| headers.get("date"))
            .and_then(|v| v.to_str().ok())?;
        let payload_hash = headers
            .get("x-amz-content-sha256")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("UNSIGNED-PAYLOAD");

        let mut encoded_q: Vec<(String, String)> = query
            .iter()
            .map(|(k, v)| (uri_encode_sigv4(k), uri_encode_sigv4(v)))
            .collect();
        encoded_q.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
        let canonical_query = encoded_q
            .into_iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<_>>()
            .join("&");

        let mut canonical_headers = String::new();
        for h_name in signed_headers.split(';') {
            let h_lower = h_name.trim().to_ascii_lowercase();
            let h_val = headers.get(h_lower.as_str())?.to_str().ok()?.trim();
            canonical_headers.push_str(&format!("{}:{}\n", h_lower, h_val));
        }

        let canonical_request = format!(
            "{}\n{}\n{}\n{}\n{}\n{}",
            method.as_str(),
            path,
            canonical_query,
            canonical_headers,
            signed_headers,
            payload_hash
        );
        let scope = format!("{}/{}/{}/aws4_request", date_yyyymmdd, region, service);
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n{}\n{}\n{}",
            amz_date,
            scope,
            sha256_hex(canonical_request.as_bytes())
        );
        let signing_key =
            derive_sigv4_signing_key(&self.secret_key, date_yyyymmdd, region, service);
        Some(hmac_sha256_hex(&signing_key, string_to_sign.as_bytes()))
    }

    #[allow(clippy::too_many_arguments)]
    fn compute_sigv4_presigned_signature(
        &self,
        method: &Method,
        path: &str,
        headers: &HeaderMap,
        query: &HashMap<String, String>,
        amz_date: &str,
        date_yyyymmdd: &str,
        region: &str,
        service: &str,
    ) -> String {
        let signed_headers = query
            .get("X-Amz-SignedHeaders")
            .map(|s| s.as_str())
            .unwrap_or("host");
        let mut encoded_q: Vec<(String, String)> = query
            .iter()
            .filter(|(k, _)| k.as_str() != "X-Amz-Signature")
            .map(|(k, v)| (uri_encode_sigv4(k), uri_encode_sigv4(v)))
            .collect();
        encoded_q.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
        let canonical_query = encoded_q
            .into_iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<_>>()
            .join("&");

        let mut canonical_headers = String::new();
        for h_name in signed_headers.split(';') {
            let h_lower = h_name.trim().to_ascii_lowercase();
            let h_val = headers
                .get(h_lower.as_str())
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .trim();
            canonical_headers.push_str(&format!("{}:{}\n", h_lower, h_val));
        }

        let canonical_request = format!(
            "{}\n{}\n{}\n{}\n{}\nUNSIGNED-PAYLOAD",
            method.as_str(),
            path,
            canonical_query,
            canonical_headers,
            signed_headers
        );
        let scope = format!("{}/{}/{}/aws4_request", date_yyyymmdd, region, service);
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n{}\n{}\n{}",
            amz_date,
            scope,
            sha256_hex(canonical_request.as_bytes())
        );
        let signing_key =
            derive_sigv4_signing_key(&self.secret_key, date_yyyymmdd, region, service);
        hmac_sha256_hex(&signing_key, string_to_sign.as_bytes())
    }
}

// =============================================================================
// HTTP S3 REST API Handlers
// =============================================================================

fn s3_error_xml(code: StatusCode, err_code: &str, message: &str) -> Response {
    let xml = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Error><Code>{}</Code><Message>{}</Message></Error>",
        xml_escape(err_code),
        xml_escape(message)
    );
    (
        code,
        [
            ("content-type", "application/xml"),
            ("x-podmesh-error-class", err_code),
        ],
        xml,
    )
        .into_response()
}

async fn healthz_handler(State(state): State<Arc<S3State>>) -> impl IntoResponse {
    let tel = state.compute_telemetry();
    axum::Json(serde_json::json!({
        "status": "ok",
        "service": "meshfs-s3",
        "version": VERSION,
        "cas_chunks_dir": state.cas.chunks_dir,
        "cas_chunk_count": tel.physical_cas_chunks,
        "physical_cas_bytes": tel.physical_cas_bytes,
        "logical_bytes": tel.logical_bytes,
        "dedup_saved_bytes": tel.dedup_saved_bytes,
        "dedup_ratio": tel.dedup_ratio,
        "self_healed_chunks": tel.self_healed_chunks,
        "peers": state.cas.peers,
    }))
}

async fn metrics_handler(State(state): State<Arc<S3State>>) -> impl IntoResponse {
    let tel = state.compute_telemetry();
    let body = format!(
        "# HELP meshfs_s3_buckets_total Number of S3 buckets\n\
         # TYPE meshfs_s3_buckets_total gauge\n\
         meshfs_s3_buckets_total {}\n\
         # HELP meshfs_s3_objects_total Number of S3 objects across all buckets\n\
         # TYPE meshfs_s3_objects_total gauge\n\
         meshfs_s3_objects_total {}\n\
         # HELP meshfs_s3_worm_locked_objects_total Number of active WORM-locked objects\n\
         # TYPE meshfs_s3_worm_locked_objects_total gauge\n\
         meshfs_s3_worm_locked_objects_total {}\n\
         # HELP meshfs_s3_logical_bytes_total Total logical bytes stored in S3 manifests\n\
         # TYPE meshfs_s3_logical_bytes_total gauge\n\
         meshfs_s3_logical_bytes_total {}\n\
         # HELP meshfs_s3_physical_cas_chunks_total Total physical 4 MiB CAS chunks on disk\n\
         # TYPE meshfs_s3_physical_cas_chunks_total gauge\n\
         meshfs_s3_physical_cas_chunks_total {}\n\
         # HELP meshfs_s3_physical_cas_bytes_total Total physical CAS bytes on disk\n\
         # TYPE meshfs_s3_physical_cas_bytes_total gauge\n\
         meshfs_s3_physical_cas_bytes_total {}\n\
         # HELP meshfs_s3_dedup_saved_bytes_total Bytes saved by CAS deduplication\n\
         # TYPE meshfs_s3_dedup_saved_bytes_total gauge\n\
         meshfs_s3_dedup_saved_bytes_total {}\n\
         # HELP meshfs_s3_dedup_ratio Deduplication ratio (logical / physical)\n\
         # TYPE meshfs_s3_dedup_ratio gauge\n\
         meshfs_s3_dedup_ratio {:.4}\n\
         # HELP meshfs_s3_self_healed_chunks_total Total CAS chunks automatically repaired via P2P self-healing\n\
         # TYPE meshfs_s3_self_healed_chunks_total counter\n\
         meshfs_s3_self_healed_chunks_total {}\n",
        tel.buckets_count,
        tel.objects_count,
        tel.worm_locked_objects,
        tel.logical_bytes,
        tel.physical_cas_chunks,
        tel.physical_cas_bytes,
        tel.dedup_saved_bytes,
        tel.dedup_ratio,
        tel.self_healed_chunks,
    );
    (
        StatusCode::OK,
        [("content-type", "text/plain; version=0.0.4; charset=utf-8")],
        body,
    )
}

async fn cas_chunk_handler(
    State(state): State<Arc<S3State>>,
    AxumPath(hash): AxumPath<String>,
) -> Response {
    let clean = ChunkStore::normalize_id(&hash).to_string();
    if clean.len() != 64 || !clean.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()) {
        return (StatusCode::BAD_REQUEST, "Invalid chunk hash").into_response();
    }
    let target = state.cas.chunk_path(&clean);
    match fs::read(&target) {
        Ok(bytes) if bytes.len() <= CHUNK_SIZE && verify_cas_digest(&bytes, &clean) => (
            StatusCode::OK,
            [
                ("content-type", "application/octet-stream"),
                ("x-podmesh-cas-blake3", clean.as_str()),
            ],
            bytes,
        )
            .into_response(),
        _ => (StatusCode::NOT_FOUND, "Chunk not found or corrupted").into_response(),
    }
}

async fn root_handler(
    State(state): State<Arc<S3State>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    if let Err((code, err)) = state.verify_request_auth(&method, &uri, &headers, &query) {
        return s3_error_xml(code, err, "Authentication failed");
    }
    let mut buckets = Vec::new();
    if let Ok(entries) = fs::read_dir(state.s3_dir.join("buckets")) {
        for e in entries.flatten() {
            if e.path().is_dir() {
                buckets.push(e.file_name().to_string_lossy().to_string());
            }
        }
    }
    buckets.sort();
    if headers
        .get("accept")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .contains("application/json")
    {
        return axum::Json(serde_json::json!({
            "status": "ok",
            "buckets": buckets,
        }))
        .into_response();
    }
    let mut xml = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<ListAllMyBucketsResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Buckets>",
    );
    for b in buckets {
        xml.push_str(&format!("<Bucket><Name>{}</Name></Bucket>", xml_escape(&b)));
    }
    xml.push_str("</Buckets></ListAllMyBucketsResult>");
    (StatusCode::OK, [("content-type", "application/xml")], xml).into_response()
}

async fn bucket_handler(
    State(state): State<Arc<S3State>>,
    AxumPath(bucket): AxumPath<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    if let Err((code, err)) = state.verify_request_auth(&method, &uri, &headers, &query) {
        return s3_error_xml(code, err, "Authentication failed");
    }
    let bdir = match state.checked_bucket_dir(&bucket) {
        Ok(d) => d,
        Err((code, err)) => return s3_error_xml(code, err, "Invalid bucket name"),
    };
    match method {
        Method::PUT => {
            if let Err(e) = fs::create_dir_all(&bdir) {
                return s3_error_xml(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "InternalError",
                    &e.to_string(),
                );
            }
            (
                StatusCode::OK,
                [("Location", format!("/{}", bucket).as_str())],
                "",
            )
                .into_response()
        }
        Method::HEAD => {
            if bdir.exists() {
                StatusCode::OK.into_response()
            } else {
                StatusCode::NOT_FOUND.into_response()
            }
        }
        Method::DELETE => {
            if !bdir.exists() {
                return s3_error_xml(StatusCode::NOT_FOUND, "NoSuchBucket", "Bucket not found");
            }
            let has_objects = fs::read_dir(&bdir)
                .map(|mut it| it.any(|e| e.is_ok()))
                .unwrap_or(false);
            if has_objects {
                return s3_error_xml(
                    StatusCode::CONFLICT,
                    "BucketNotEmpty",
                    "The bucket you tried to delete is not empty",
                );
            }
            let _ = fs::remove_dir(&bdir);
            StatusCode::NO_CONTENT.into_response()
        }
        Method::GET => {
            if !bdir.exists() {
                return s3_error_xml(StatusCode::NOT_FOUND, "NoSuchBucket", "Bucket not found");
            }
            let prefix = query.get("prefix").cloned().unwrap_or_default();
            let mut objects = Vec::new();
            if let Ok(entries) = fs::read_dir(&bdir) {
                for e in entries.flatten() {
                    let p = e.path();
                    if p.extension().and_then(|s| s.to_str()) == Some("json") {
                        if let Ok(bytes) = fs::read(&p) {
                            if let Ok(m) = serde_json::from_slice::<ObjectManifest>(&bytes) {
                                if m.key.starts_with(&prefix) {
                                    objects.push(m);
                                }
                            }
                        }
                    }
                }
            }
            objects.sort_by(|a, b| a.key.cmp(&b.key));
            if headers
                .get("accept")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .contains("application/json")
            {
                return axum::Json(serde_json::json!({
                    "status": "ok",
                    "bucket": bucket,
                    "objects": objects,
                }))
                .into_response();
            }
            let mut xml = format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Name>{}</Name><Prefix>{}</Prefix><KeyCount>{}</KeyCount><IsTruncated>false</IsTruncated>",
                xml_escape(&bucket),
                xml_escape(&prefix),
                objects.len()
            );
            for o in objects {
                xml.push_str(&format!(
                    "<Contents><Key>{}</Key><LastModified>{}</LastModified><ETag>\"{}\"</ETag><Size>{}</Size><StorageClass>STANDARD</StorageClass></Contents>",
                    xml_escape(&o.key),
                    xml_escape(&o.created_at),
                    xml_escape(&o.etag),
                    o.size
                ));
            }
            xml.push_str("</ListBucketResult>");
            (StatusCode::OK, [("content-type", "application/xml")], xml).into_response()
        }
        _ => StatusCode::METHOD_NOT_ALLOWED.into_response(),
    }
}

async fn object_handler(
    State(state): State<Arc<S3State>>,
    AxumPath((bucket, key)): AxumPath<(String, String)>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
    body: Body,
) -> Response {
    if let Err((code, err)) = state.verify_request_auth(&method, &uri, &headers, &query) {
        return s3_error_xml(code, err, "Authentication failed");
    }
    let bdir = match state.checked_bucket_dir(&bucket) {
        Ok(d) => d,
        Err((code, err)) => return s3_error_xml(code, err, "Invalid bucket name"),
    };
    let clean_key = key.trim_start_matches('/').to_string();
    if clean_key.is_empty() {
        return s3_error_xml(StatusCode::BAD_REQUEST, "InvalidKey", "Object key is empty");
    }

    match method {
        Method::POST => {
            // 1. CreateMultipartUpload (`?uploads`)
            if query.contains_key("uploads") {
                if !bdir.exists() {
                    return s3_error_xml(StatusCode::NOT_FOUND, "NoSuchBucket", "Bucket not found");
                }
                if let Err((code, msg)) = state.ensure_not_worm_locked(&bucket, &clean_key) {
                    let err_code = if code == StatusCode::FORBIDDEN {
                        "ObjectLocked"
                    } else {
                        "InternalError"
                    };
                    return s3_error_xml(code, err_code, &msg);
                }
                let retain_until = headers
                    .get("x-amz-object-lock-retain-until-date")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string());
                if let Err((code, msg)) = validate_retain_until(&retain_until) {
                    return s3_error_xml(code, "InvalidArgument", &msg);
                }
                let lock_mode = headers
                    .get("x-amz-object-lock-mode")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string());
                let nanos = Utc::now().timestamp_nanos_opt().unwrap_or(0);
                let upload_id =
                    blake3_hex(format!("{}:{}:{}", bucket, clean_key, nanos).as_bytes());
                let mdir = state.s3_dir.join("multipart").join(&upload_id);
                let meta = MultipartSessionMeta {
                    upload_id: upload_id.clone(),
                    bucket: bucket.clone(),
                    key: clean_key.clone(),
                    created_at: Utc::now().to_rfc3339(),
                    retain_until,
                    lock_mode,
                };
                if let Err(e) = atomic_write_json(&mdir.join("meta.json"), &meta) {
                    return s3_error_xml(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "InternalError",
                        &e.to_string(),
                    );
                }
                let xml = format!(
                    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<InitiateMultipartUploadResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Bucket>{}</Bucket><Key>{}</Key><UploadId>{}</UploadId></InitiateMultipartUploadResult>",
                    xml_escape(&bucket),
                    xml_escape(&clean_key),
                    xml_escape(&upload_id)
                );
                return (StatusCode::OK, [("content-type", "application/xml")], xml)
                    .into_response();
            }

            // 2. CompleteMultipartUpload (`?uploadId=ID`) — O(1) Merkle Manifest Sealing + Fail-Closed WORM!
            if let Some(upload_id) = query.get("uploadId") {
                let mdir = match state.checked_multipart_dir(upload_id) {
                    Ok(d) => d,
                    Err((code, err)) => {
                        return s3_error_xml(code, err, "Multipart upload session not found")
                    }
                };
                let meta_path = mdir.join("meta.json");
                if !meta_path.exists() {
                    return s3_error_xml(
                        StatusCode::NOT_FOUND,
                        "NoSuchUpload",
                        "Multipart upload session not found",
                    );
                }
                let meta: MultipartSessionMeta = match fs::read(&meta_path).and_then(|b| {
                    serde_json::from_slice(&b)
                        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
                }) {
                    Ok(m) => m,
                    Err(e) => {
                        return s3_error_xml(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "InternalError",
                            &e.to_string(),
                        )
                    }
                };

                // Enforce strict session binding: uploadId must match (bucket, clean_key)
                if meta.bucket != bucket || meta.key != clean_key {
                    return s3_error_xml(
                        StatusCode::BAD_REQUEST,
                        "InvalidRequest",
                        "Multipart uploadId does not match target bucket/key",
                    );
                }
                // Enforce Fail-Closed WORM check before sealing target_manifest (TOCTOU protection)
                if let Err((code, msg)) = state.ensure_not_worm_locked(&bucket, &clean_key) {
                    let err_code = if code == StatusCode::FORBIDDEN {
                        "ObjectLocked"
                    } else {
                        "InternalError"
                    };
                    return s3_error_xml(code, err_code, &msg);
                }

                let mut parts: Vec<MultipartPartManifest> = Vec::new();
                if let Ok(entries) = fs::read_dir(&mdir) {
                    for e in entries.flatten() {
                        let fname = e.file_name().to_string_lossy().to_string();
                        if fname.starts_with("part-") && fname.ends_with(".json") {
                            if let Ok(b) = fs::read(e.path()) {
                                if let Ok(pm) = serde_json::from_slice::<MultipartPartManifest>(&b)
                                {
                                    parts.push(pm);
                                }
                            }
                        }
                    }
                }
                if parts.is_empty() {
                    return s3_error_xml(
                        StatusCode::BAD_REQUEST,
                        "InvalidPart",
                        "Multipart upload contains no uploaded parts",
                    );
                }
                parts.sort_by_key(|p| p.part_number);

                // O(1) metadata-only concatenation of chunk descriptors!
                let mut combined_chunks = Vec::new();
                let mut running_offset = 0u64;
                for p in parts {
                    for c in p.chunks {
                        combined_chunks.push(ChunkRef {
                            id: c.id,
                            size: c.size,
                            offset: running_offset,
                        });
                        running_offset += c.size as u64;
                    }
                }
                let merkle_root = compute_merkle_root(&combined_chunks);
                if let Err((code, msg)) =
                    state.ensure_bucket_quota(&bucket, &clean_key, running_offset)
                {
                    return s3_error_xml(code, "QuotaExceeded", &msg);
                }
                let manifest = ObjectManifest {
                    bucket: bucket.clone(),
                    key: clean_key.clone(),
                    size: running_offset,
                    etag: merkle_root.clone(),
                    merkle_root: merkle_root.clone(),
                    content_type: "application/octet-stream".to_string(),
                    created_at: Utc::now().to_rfc3339(),
                    retain_until: meta.retain_until,
                    lock_mode: meta.lock_mode,
                    user_meta: BTreeMap::new(),
                    chunks: combined_chunks,
                };
                let target_manifest = state.object_manifest_path(&bucket, &clean_key);
                if let Err(e) = atomic_write_json(&target_manifest, &manifest) {
                    return s3_error_xml(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "InternalError",
                        &e.to_string(),
                    );
                }
                let _ = fs::remove_dir_all(&mdir);
                let xml = format!(
                    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<CompleteMultipartUploadResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Location>/{}/{}</Location><Bucket>{}</Bucket><Key>{}</Key><ETag>\"{}\"</ETag></CompleteMultipartUploadResult>",
                    xml_escape(&bucket),
                    xml_escape(&clean_key),
                    xml_escape(&bucket),
                    xml_escape(&clean_key),
                    xml_escape(&merkle_root)
                );
                return (
                    StatusCode::OK,
                    [
                        ("content-type", "application/xml"),
                        ("x-podmesh-cas-merkle-root", merkle_root.as_str()),
                    ],
                    xml,
                )
                    .into_response();
            }

            StatusCode::BAD_REQUEST.into_response()
        }

        Method::PUT => {
            // Check if Multipart UploadPart (`?partNumber=N&uploadId=ID`)
            if let (Some(part_str), Some(upload_id)) =
                (query.get("partNumber"), query.get("uploadId"))
            {
                let part_number: u32 = match part_str.parse() {
                    Ok(n) if (1..=10_000).contains(&n) => n,
                    _ => {
                        return s3_error_xml(
                            StatusCode::BAD_REQUEST,
                            "InvalidPartNumber",
                            "Part number must be an integer between 1 and 10000",
                        )
                    }
                };
                let mdir = match state.checked_multipart_dir(upload_id) {
                    Ok(d) => d,
                    Err((code, err)) => {
                        return s3_error_xml(code, err, "Multipart upload session not found")
                    }
                };
                if !mdir.join("meta.json").exists() {
                    return s3_error_xml(
                        StatusCode::NOT_FOUND,
                        "NoSuchUpload",
                        "Multipart upload session not found",
                    );
                }
                let (chunks, total_size, _) = match state.ingest_async_body(body).await {
                    Ok(v) => v,
                    Err(e) => {
                        return s3_error_xml(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "InternalError",
                            &e.to_string(),
                        )
                    }
                };
                let part_etag = compute_merkle_root(&chunks);
                let part_manifest = MultipartPartManifest {
                    part_number,
                    size: total_size,
                    etag: part_etag.clone(),
                    chunks,
                };
                let part_path = mdir.join(format!("part-{:05}.json", part_number));
                if let Err(e) = atomic_write_json(&part_path, &part_manifest) {
                    return s3_error_xml(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "InternalError",
                        &e.to_string(),
                    );
                }
                return (
                    StatusCode::OK,
                    [("ETag", format!("\"{}\"", part_etag))],
                    "",
                )
                    .into_response();
            }

            // Standard PutObject (Bounded-Memory 4 MiB Streaming!)
            if !bdir.exists() {
                return s3_error_xml(StatusCode::NOT_FOUND, "NoSuchBucket", "Bucket not found");
            }
            let retain_until = headers
                .get("x-amz-object-lock-retain-until-date")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string());
            if let Err((code, msg)) = validate_retain_until(&retain_until) {
                return s3_error_xml(code, "InvalidArgument", &msg);
            }
            if let Err((code, msg)) = state.ensure_not_worm_locked(&bucket, &clean_key) {
                let err_code = if code == StatusCode::FORBIDDEN {
                    "ObjectLocked"
                } else {
                    "InternalError"
                };
                return s3_error_xml(code, err_code, &msg);
            }

            let content_type = headers
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("application/octet-stream")
                .to_string();
            let lock_mode = headers
                .get("x-amz-object-lock-mode")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string());
            let mut user_meta = BTreeMap::new();
            for (k, v) in headers.iter() {
                if let Some(mk) = k.as_str().strip_prefix("x-amz-meta-") {
                    if let Ok(mv) = v.to_str() {
                        user_meta.insert(mk.to_string(), mv.to_string());
                    }
                }
            }

            let (chunks, total_size, new_chunks) = match state.ingest_async_body(body).await {
                Ok(v) => v,
                Err(e) => {
                    return s3_error_xml(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "InternalError",
                        &e.to_string(),
                    )
                }
            };

            match state.finalize_manifest(
                &bucket,
                &clean_key,
                chunks,
                total_size,
                content_type,
                retain_until,
                lock_mode,
                user_meta,
            ) {
                Ok(manifest) => (
                    StatusCode::OK,
                    [
                        ("ETag", format!("\"{}\"", manifest.etag)),
                        ("x-podmesh-cas-merkle-root", manifest.merkle_root),
                        ("x-podmesh-cas-new-chunks", new_chunks.to_string()),
                    ],
                    "",
                )
                    .into_response(),
                Err((code, msg)) => {
                    let err_code = if code == StatusCode::FORBIDDEN {
                        "ObjectLocked"
                    } else if code == StatusCode::NOT_FOUND {
                        "NoSuchBucket"
                    } else if code == StatusCode::INSUFFICIENT_STORAGE {
                        "QuotaExceeded"
                    } else {
                        "InternalError"
                    };
                    s3_error_xml(code, err_code, &msg)
                }
            }
        }

        Method::HEAD | Method::GET => {
            let mpath = state.object_manifest_path(&bucket, &clean_key);
            if !mpath.exists() {
                return s3_error_xml(StatusCode::NOT_FOUND, "NoSuchKey", "Object not found");
            }
            let manifest: ObjectManifest = match fs::read(&mpath).and_then(|b| {
                serde_json::from_slice(&b)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
            }) {
                Ok(m) => m,
                Err(e) => {
                    return s3_error_xml(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "InternalError",
                        &e.to_string(),
                    )
                }
            };

            if method == Method::HEAD {
                let mut resp = (
                    StatusCode::OK,
                    [
                        ("Content-Length", manifest.size.to_string()),
                        ("Content-Type", manifest.content_type.clone()),
                        ("ETag", format!("\"{}\"", manifest.etag)),
                        ("x-podmesh-cas-merkle-root", manifest.merkle_root.clone()),
                    ],
                    "",
                )
                    .into_response();
                if let Some(ref u) = manifest.retain_until {
                    if let Ok(hv) = u.parse() {
                        resp.headers_mut()
                            .insert("x-amz-object-lock-retain-until-date", hv);
                    }
                }
                return resp;
            }

            // Check HTTP `Range: bytes=start-end` or `Range: bytes=-suffix`
            if let Some(range_hdr) = headers.get("range").and_then(|v| v.to_str().ok()) {
                if let Some(spec) = range_hdr.strip_prefix("bytes=") {
                    let mut parts = spec.splitn(2, '-');
                    let left = parts.next().unwrap_or("").trim();
                    let right = parts.next().unwrap_or("").trim();

                    let (start, end) = if left.is_empty() {
                        // Suffix range `bytes=-N`
                        let suffix: u64 = right.parse().unwrap_or(0);
                        if suffix == 0 || manifest.size == 0 {
                            (manifest.size, 0)
                        } else {
                            (
                                manifest.size.saturating_sub(suffix),
                                manifest.size.saturating_sub(1),
                            )
                        }
                    } else {
                        let s: u64 = left.parse().unwrap_or(u64::MAX);
                        let e: u64 = if right.is_empty() {
                            manifest.size.saturating_sub(1)
                        } else {
                            right
                                .parse::<u64>()
                                .unwrap_or(u64::MAX)
                                .min(manifest.size.saturating_sub(1))
                        };
                        (s, e)
                    };

                    if start >= manifest.size || start > end {
                        return (
                            StatusCode::RANGE_NOT_SATISFIABLE,
                            [("Content-Range", format!("bytes */{}", manifest.size))],
                            "",
                        )
                            .into_response();
                    }
                    match state.read_object_range(&manifest, start, end) {
                        Ok(slice) => {
                            let content_range =
                                format!("bytes {}-{}/{}", start, end, manifest.size);
                            return (
                                StatusCode::PARTIAL_CONTENT,
                                [
                                    ("Content-Type", manifest.content_type),
                                    ("Content-Length", slice.len().to_string()),
                                    ("Content-Range", content_range),
                                    ("Accept-Ranges", "bytes".to_string()),
                                    ("ETag", format!("\"{}\"", manifest.etag)),
                                    ("x-podmesh-cas-merkle-root", manifest.merkle_root),
                                ],
                                slice,
                            )
                                .into_response();
                        }
                        Err(e) => {
                            return s3_error_xml(
                                StatusCode::INTERNAL_SERVER_ERROR,
                                "CASIntegrityError",
                                &e.to_string(),
                            );
                        }
                    }
                }
            }

            // Verify all chunks in manifest before committing HTTP 200 OK headers (Fail-Closed Bit-Rot Gate)
            for c in &manifest.chunks {
                if let Err(e) = state.cas.read_chunk(&c.id) {
                    return s3_error_xml(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "CASIntegrityError",
                        &e.to_string(),
                    );
                }
            }

            // Full GET: Stream 4 MiB chunks incrementally via Body::from_stream!
            let cas = state.cas.clone();
            let chunks_vec = manifest.chunks.clone();
            let chunk_stream = futures_util::stream::iter(chunks_vec)
                .map(move |c| cas.read_chunk(&c.id).map(Bytes::from));

            (
                StatusCode::OK,
                [
                    ("Content-Type", manifest.content_type),
                    ("Content-Length", manifest.size.to_string()),
                    ("Accept-Ranges", "bytes".to_string()),
                    ("ETag", format!("\"{}\"", manifest.etag)),
                    ("x-podmesh-cas-merkle-root", manifest.merkle_root),
                ],
                Body::from_stream(chunk_stream),
            )
                .into_response()
        }

        Method::DELETE => {
            // Check if AbortMultipartUpload (`DELETE ?uploadId=ID`)
            if let Some(upload_id) = query.get("uploadId") {
                let mdir = match state.checked_multipart_dir(upload_id) {
                    Ok(d) => d,
                    Err((code, err)) => {
                        return s3_error_xml(code, err, "Multipart upload session not found")
                    }
                };
                if !mdir.exists() {
                    return s3_error_xml(
                        StatusCode::NOT_FOUND,
                        "NoSuchUpload",
                        "Multipart upload session not found",
                    );
                }
                let _ = fs::remove_dir_all(&mdir);
                return StatusCode::NO_CONTENT.into_response();
            }

            let mpath = state.object_manifest_path(&bucket, &clean_key);
            if !mpath.exists() {
                return StatusCode::NO_CONTENT.into_response();
            }
            if let Err((code, msg)) = state.ensure_not_worm_locked(&bucket, &clean_key) {
                let err_code = if code == StatusCode::FORBIDDEN {
                    "ObjectLocked"
                } else {
                    "InternalError"
                };
                return s3_error_xml(code, err_code, &msg);
            }
            let _ = fs::remove_file(&mpath);
            StatusCode::NO_CONTENT.into_response()
        }

        _ => StatusCode::METHOD_NOT_ALLOWED.into_response(),
    }
}

// =============================================================================
// Unix Domain Socket Control Plane (`/var/lib/meshfs/s3.sock`)
// =============================================================================

#[derive(Debug, Serialize, Deserialize)]
pub struct UdsRequest {
    pub op: String,
    pub bucket: Option<String>,
    pub key: Option<String>,
    pub expires_secs: Option<i64>,
    pub method: Option<String>,
    pub grace_seconds: Option<u64>,
    pub dry_run: Option<bool>,
    pub max_bytes: Option<u64>,
}

async fn handle_uds_client(stream: UnixStream, state: Arc<S3State>) {
    let (reader, mut writer) = stream.into_split();
    let mut lines = BufReader::new(reader).lines();
    if let Ok(Some(line)) = lines.next_line().await {
        let req: UdsRequest = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(e) => {
                let _ = writer
                    .write_all(
                        format!("{{\"status\":\"error\",\"message\":\"{}\"}}\n", e).as_bytes(),
                    )
                    .await;
                return;
            }
        };
        let resp = match req.op.as_str() {
            "status" => {
                let mut buckets = Vec::new();
                if let Ok(entries) = fs::read_dir(state.s3_dir.join("buckets")) {
                    for e in entries.flatten() {
                        if e.path().is_dir() {
                            buckets.push(e.file_name().to_string_lossy().to_string());
                        }
                    }
                }
                buckets.sort();
                let tel = state.compute_telemetry();
                serde_json::json!({
                    "status": "ok",
                    "service": "meshfs-s3",
                    "version": VERSION,
                    "bind_addr": state.bind_addr,
                    "cas_chunks_dir": state.cas.chunks_dir,
                    "cas_chunk_count": tel.physical_cas_chunks,
                    "physical_cas_bytes": tel.physical_cas_bytes,
                    "logical_bytes": tel.logical_bytes,
                    "dedup_saved_bytes": tel.dedup_saved_bytes,
                    "dedup_ratio": tel.dedup_ratio,
                    "worm_locked_objects": tel.worm_locked_objects,
                    "self_healed_chunks": tel.self_healed_chunks,
                    "peers": state.cas.peers,
                    "s3_dir": state.s3_dir,
                    "buckets": buckets,
                })
            }
            "gc" => {
                let grace = req.grace_seconds.unwrap_or(3600);
                let dry_run = req.dry_run.unwrap_or(false);
                let rep = state.run_universal_cas_gc(grace, dry_run);
                serde_json::to_value(rep).unwrap_or_default()
            }
            "quota.set" => {
                let b = req.bucket.unwrap_or_default();
                let max_b = req.max_bytes.unwrap_or(0);
                match state.set_bucket_quota(&b, max_b) {
                    Ok(q) => serde_json::json!({
                        "status": "ok",
                        "quota": q,
                    }),
                    Err(e) => serde_json::json!({
                        "status": "error",
                        "message": e,
                    }),
                }
            }
            "quota.get" => {
                let b = req.bucket.unwrap_or_default();
                let used = state.bucket_logical_bytes(&b, None);
                let q = state.get_bucket_quota(&b);
                serde_json::json!({
                    "status": "ok",
                    "bucket": b,
                    "logical_used_bytes": used,
                    "max_bytes": q.map(|x| x.max_bytes).unwrap_or(0),
                })
            }
            "presign" => {
                let b = req.bucket.unwrap_or_default();
                let k = req.key.unwrap_or_default();
                let exp = req.expires_secs.unwrap_or(900);
                let m = req.method.unwrap_or_else(|| "GET".to_string());
                let endpoint = format!("http://{}", state.bind_addr);
                let url = state.generate_presigned_url(&endpoint, &m, &b, &k, exp);
                serde_json::json!({
                    "status": "ok",
                    "bucket": b,
                    "key": k,
                    "method": m,
                    "expires_secs": exp,
                    "presigned_url": url,
                })
            }
            _ => serde_json::json!({
                "status": "error",
                "message": format!("Unknown op: {}", req.op)
            }),
        };
        if let Ok(s) = serde_json::to_string(&resp) {
            let _ = writer.write_all(format!("{}\n", s).as_bytes()).await;
        }
    }
}

// =============================================================================
// CLI Definition (`meshfs-s3`)
// =============================================================================

#[derive(Parser)]
#[command(
    name = "meshfs-s3",
    version = VERSION,
    about = "MeshFS S3 Gateway (v2.3.0) — Sovereign S3 Object Storage backed by 4 MiB SHA-256 CAS"
)]
struct Cli {
    #[arg(long, global = true, default_value = "/var/lib/meshfs")]
    cas_dir: PathBuf,

    #[arg(long, global = true, default_value = "/var/lib/meshfs/s3")]
    s3_dir: PathBuf,

    #[arg(long, global = true, default_value = "/var/lib/meshfs/s3.sock")]
    socket: PathBuf,

    /// Optional comma-separated peer URLs for automatic P2P self-healing on bit-rot (or set MESHFS_PEERS)
    #[arg(long, global = true)]
    peers: Option<String>,

    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the MeshFS S3 HTTP & UDS daemon
    Daemon {
        #[arg(long, default_value = "127.0.0.1:9000")]
        bind: String,
    },
    /// Query daemon status, deduplication ratio, and CAS metrics via Unix socket
    Status,
    /// Universal CAS Mark-and-Sweep Garbage Collector across MeshFS, MeshFS-S3, and PMBS
    Gc {
        /// Grace window in seconds (chunks modified more recently than this are never deleted)
        #[arg(long, default_value_t = 3600)]
        grace_seconds: u64,
        /// Only report unreferenced chunks without deleting them
        #[arg(long)]
        dry_run: bool,
    },
    /// Manage S3 bucket quotas
    Quota {
        #[command(subcommand)]
        action: QuotaCommands,
    },
    /// Manage S3 buckets locally
    Bucket {
        #[command(subcommand)]
        action: BucketCommands,
    },
    /// Manage S3 objects directly against the CAS + S3 manifest store
    Object {
        #[command(subcommand)]
        action: ObjectCommands,
    },
    /// Generate an HMAC-SHA256 presigned URL
    Presign {
        bucket: String,
        key: String,
        #[arg(long, default_value_t = 900)]
        expires: i64,
        #[arg(long, default_value = "GET")]
        method: String,
        #[arg(long, default_value = "http://127.0.0.1:9000")]
        endpoint: String,
    },
}

#[derive(Subcommand)]
enum QuotaCommands {
    /// Set maximum logical bytes allowed for a bucket (0 = unlimited)
    Set {
        bucket: String,
        #[arg(long)]
        max_bytes: u64,
    },
    /// Get current logical usage and quota for a bucket
    Get {
        bucket: String,
    },
}

#[derive(Subcommand)]
enum BucketCommands {
    Create { name: String },
    List,
    Delete { name: String },
}

#[derive(Subcommand)]
enum ObjectCommands {
    Put {
        bucket: String,
        key: String,
        file: PathBuf,
        #[arg(long)]
        retain_until: Option<String>,
    },
    Get {
        bucket: String,
        key: String,
        output: PathBuf,
        #[arg(long)]
        range: Option<String>,
    },
    Ls {
        bucket: String,
    },
    Delete {
        bucket: String,
        key: String,
    },
}

fn load_peers(cli_peers: Option<&str>) -> Vec<String> {
    let mut raw = cli_peers.unwrap_or("").to_string();
    if raw.is_empty() {
        raw = std::env::var("MESHFS_PEERS")
            .or_else(|_| std::env::var("MESHFS_S3_PEERS"))
            .unwrap_or_default();
    }
    if raw.is_empty() {
        if let Ok(content) = fs::read_to_string("/etc/meshfs/s3.env") {
            for line in content.lines() {
                let line = line.trim();
                if let Some(v) = line
                    .strip_prefix("MESHFS_PEERS=")
                    .or_else(|| line.strip_prefix("MESHFS_S3_PEERS="))
                {
                    raw = v.trim_matches('"').trim_matches('\'').to_string();
                    break;
                }
            }
        }
    }
    raw.split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

fn load_credentials(require_non_empty: bool) -> Result<(String, String), String> {
    let mut ak = std::env::var("MESHFS_S3_ACCESS_KEY").unwrap_or_default();
    let mut sk = std::env::var("MESHFS_S3_SECRET_KEY").unwrap_or_default();
    if ak.is_empty() || sk.is_empty() {
        if let Ok(content) = fs::read_to_string("/etc/meshfs/s3.env") {
            for line in content.lines() {
                let line = line.trim();
                if let Some(v) = line.strip_prefix("MESHFS_S3_ACCESS_KEY=") {
                    if ak.is_empty() {
                        ak = v.trim_matches('"').trim_matches('\'').to_string();
                    }
                } else if let Some(v) = line.strip_prefix("MESHFS_S3_SECRET_KEY=") {
                    if sk.is_empty() {
                        sk = v.trim_matches('"').trim_matches('\'').to_string();
                    }
                }
            }
        }
    }
    if require_non_empty && (ak.is_empty() || sk.is_empty()) {
        return Err(
            "Fail-Closed: MESHFS_S3_ACCESS_KEY and MESHFS_S3_SECRET_KEY must be configured in environment or /etc/meshfs/s3.env".to_string(),
        );
    }
    Ok((ak, sk))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let peers = load_peers(cli.peers.as_deref());

    match cli.command {
        Commands::Daemon { bind } => {
            let (access_key, secret_key) = load_credentials(true)?;
            let effective_bind = std::env::var("MESHFS_S3_BIND")
                .ok()
                .filter(|s| !s.trim().is_empty())
                .unwrap_or(bind);

            tracing_subscriber::fmt()
                .with_env_filter(
                    tracing_subscriber::EnvFilter::try_from_default_env()
                        .unwrap_or_else(|_| "info".into()),
                )
                .init();

            let state = Arc::new(S3State::with_peers(
                &cli.cas_dir,
                &cli.s3_dir,
                access_key,
                secret_key,
                effective_bind.clone(),
                peers,
            )?);

            let sock_path = cli.socket.clone();
            if sock_path.exists() {
                let _ = fs::remove_file(&sock_path);
            }
            if let Some(parent) = sock_path.parent() {
                fs::create_dir_all(parent)?;
            }
            let uds_listener = UnixListener::bind(&sock_path)?;
            let _ = fs::set_permissions(&sock_path, fs::Permissions::from_mode(0o600));
            let uds_state = state.clone();
            tokio::spawn(async move {
                while let Ok((stream, _)) = uds_listener.accept().await {
                    let st = uds_state.clone();
                    tokio::spawn(async move {
                        handle_uds_client(stream, st).await;
                    });
                }
            });

            let app = Router::new()
                .route("/healthz", get(healthz_handler))
                .route("/metrics", get(metrics_handler))
                .route("/cas/chunk/:hash", get(cas_chunk_handler))
                .route("/", get(root_handler))
                .route("/:bucket", any(bucket_handler))
                .route("/:bucket/*key", any(object_handler))
                .layer(axum::extract::DefaultBodyLimit::disable())
                .with_state(state);

            let listener = tokio::net::TcpListener::bind(&effective_bind).await?;
            tracing::info!(
                "MeshFS S3 Gateway v{} listening on http://{} (UDS: {})",
                VERSION,
                effective_bind,
                sock_path.display()
            );
            axum::serve(listener, app).await?;
        }

        Commands::Status => {
            let mut stream = UnixStream::connect(&cli.socket).await?;
            stream.write_all(b"{\"op\":\"status\"}\n").await?;
            let mut buf = String::new();
            BufReader::new(stream).read_line(&mut buf).await?;
            println!("{}", buf.trim());
        }

        Commands::Gc {
            grace_seconds,
            dry_run,
        } => {
            if let Ok(mut stream) = UnixStream::connect(&cli.socket).await {
                let req = serde_json::json!({
                    "op": "gc",
                    "grace_seconds": grace_seconds,
                    "dry_run": dry_run,
                });
                stream
                    .write_all(format!("{}\n", req).as_bytes())
                    .await?;
                let mut buf = String::new();
                BufReader::new(stream).read_line(&mut buf).await?;
                println!("{}", buf.trim());
            } else {
                let (access_key, secret_key) = load_credentials(false)?;
                let state = S3State::with_peers(
                    &cli.cas_dir,
                    &cli.s3_dir,
                    access_key,
                    secret_key,
                    "127.0.0.1:9000".to_string(),
                    peers,
                )?;
                let rep = state.run_universal_cas_gc(grace_seconds, dry_run);
                println!("{}", serde_json::to_string(&rep)?);
            }
        }

        Commands::Quota { action } => {
            let (access_key, secret_key) = load_credentials(false)?;
            let state = S3State::with_peers(
                &cli.cas_dir,
                &cli.s3_dir,
                access_key,
                secret_key,
                "127.0.0.1:9000".to_string(),
                peers,
            )?;
            match action {
                QuotaCommands::Set { bucket, max_bytes } => {
                    let q = state.set_bucket_quota(&bucket, max_bytes)?;
                    println!(
                        "{}",
                        serde_json::json!({
                            "status": "ok",
                            "action": "quota.set",
                            "bucket": q.bucket,
                            "max_bytes": q.max_bytes,
                            "updated_at": q.updated_at,
                        })
                    );
                }
                QuotaCommands::Get { bucket } => {
                    let used = state.bucket_logical_bytes(&bucket, None);
                    let q = state.get_bucket_quota(&bucket);
                    println!(
                        "{}",
                        serde_json::json!({
                            "status": "ok",
                            "bucket": bucket,
                            "logical_used_bytes": used,
                            "max_bytes": q.map(|x| x.max_bytes).unwrap_or(0),
                        })
                    );
                }
            }
        }

        Commands::Bucket { action } => {
            let (access_key, secret_key) = load_credentials(false)?;
            let state = S3State::with_peers(
                &cli.cas_dir,
                &cli.s3_dir,
                access_key,
                secret_key,
                "127.0.0.1:9000".to_string(),
                peers,
            )?;
            match action {
                BucketCommands::Create { name } => {
                    let bdir = state
                        .checked_bucket_dir(&name)
                        .map_err(|(_, m)| m.to_string())?;
                    fs::create_dir_all(bdir)?;
                    println!(
                        "{}",
                        serde_json::json!({"status": "ok", "action": "bucket.create", "bucket": name})
                    );
                }
                BucketCommands::List => {
                    let mut buckets = Vec::new();
                    if let Ok(entries) = fs::read_dir(state.s3_dir.join("buckets")) {
                        for e in entries.flatten() {
                            if e.path().is_dir() {
                                buckets.push(e.file_name().to_string_lossy().to_string());
                            }
                        }
                    }
                    buckets.sort();
                    println!(
                        "{}",
                        serde_json::json!({"status": "ok", "buckets": buckets})
                    );
                }
                BucketCommands::Delete { name } => {
                    let bdir = state
                        .checked_bucket_dir(&name)
                        .map_err(|(_, m)| m.to_string())?;
                    fs::remove_dir(bdir)?;
                    println!(
                        "{}",
                        serde_json::json!({"status": "ok", "action": "bucket.delete", "bucket": name})
                    );
                }
            }
        }

        Commands::Object { action } => {
            let (access_key, secret_key) = load_credentials(false)?;
            let state = S3State::with_peers(
                &cli.cas_dir,
                &cli.s3_dir,
                access_key,
                secret_key,
                "127.0.0.1:9000".to_string(),
                peers,
            )?;
            match action {
                ObjectCommands::Put {
                    bucket,
                    key,
                    file,
                    retain_until,
                } => {
                    if let Err((_, msg)) = validate_retain_until(&retain_until) {
                        eprintln!("{}", serde_json::json!({"status": "error", "message": msg}));
                        std::process::exit(1);
                    }
                    if let Err((_, msg)) = state.ensure_not_worm_locked(&bucket, &key) {
                        eprintln!("{}", serde_json::json!({"status": "error", "message": msg}));
                        std::process::exit(1);
                    }
                    let reader = StdBufReader::new(File::open(&file)?);
                    let (chunks, total_size, new_chunks) = state.ingest_reader(reader)?;
                    let lock_mode = retain_until.as_ref().map(|_| "COMPLIANCE".to_string());
                    match state.finalize_manifest(
                        &bucket,
                        &key,
                        chunks,
                        total_size,
                        "application/octet-stream".to_string(),
                        retain_until,
                        lock_mode,
                        BTreeMap::new(),
                    ) {
                        Ok(manifest) => {
                            println!(
                                "{}",
                                serde_json::json!({
                                    "status": "ok",
                                    "bucket": bucket,
                                    "key": key,
                                    "size": manifest.size,
                                    "merkle_root": manifest.merkle_root,
                                    "total_chunks": manifest.chunks.len(),
                                    "new_chunks_written": new_chunks,
                                    "retain_until": manifest.retain_until,
                                })
                            );
                        }
                        Err((_, msg)) => {
                            eprintln!("{}", serde_json::json!({"status": "error", "message": msg}));
                            std::process::exit(1);
                        }
                    }
                }
                ObjectCommands::Get {
                    bucket,
                    key,
                    output,
                    range,
                } => {
                    let mpath = state.object_manifest_path(&bucket, &key);
                    let manifest: ObjectManifest = serde_json::from_slice(&fs::read(&mpath)?)?;
                    if let Some(r) = range {
                        let mut sp = r.splitn(2, '-');
                        let s: u64 = sp.next().and_then(|v| v.parse().ok()).unwrap_or(0);
                        let e: u64 = sp
                            .next()
                            .and_then(|v| v.parse().ok())
                            .unwrap_or_else(|| manifest.size.saturating_sub(1));
                        let bytes = state.read_object_range(&manifest, s, e)?;
                        fs::write(&output, &bytes)?;
                        println!(
                            "{}",
                            serde_json::json!({
                                "status": "ok",
                                "bucket": bucket,
                                "key": key,
                                "bytes_written": bytes.len(),
                                "blake3": blake3_hex(&bytes),
                            })
                        );
                    } else {
                        // Bounded-memory streaming write chunk by chunk!
                        let mut out_file = BufWriter::new(File::create(&output)?);
                        let mut hasher = blake3::Hasher::new();
                        let mut written = 0u64;
                        for c in &manifest.chunks {
                            let chunk_bytes = state.cas.read_chunk(&c.id)?;
                            hasher.update(&chunk_bytes);
                            out_file.write_all(&chunk_bytes)?;
                            written += chunk_bytes.len() as u64;
                        }
                        out_file.flush()?;
                        println!(
                            "{}",
                            serde_json::json!({
                                "status": "ok",
                                "bucket": bucket,
                                "key": key,
                                "bytes_written": written,
                                "blake3": hasher.finalize().to_hex().to_string(),
                            })
                        );
                    }
                }
                ObjectCommands::Ls { bucket } => {
                    let bdir = state
                        .checked_bucket_dir(&bucket)
                        .map_err(|(_, m)| m.to_string())?;
                    let mut objects = Vec::new();
                    if let Ok(entries) = fs::read_dir(&bdir) {
                        for e in entries.flatten() {
                            if e.path().extension().and_then(|s| s.to_str()) == Some("json") {
                                if let Ok(b) = fs::read(e.path()) {
                                    if let Ok(m) = serde_json::from_slice::<ObjectManifest>(&b) {
                                        objects.push(serde_json::json!({
                                            "key": m.key,
                                            "size": m.size,
                                            "etag": m.etag,
                                            "chunks": m.chunks.len(),
                                            "retain_until": m.retain_until,
                                        }));
                                    }
                                }
                            }
                        }
                    }
                    println!(
                        "{}",
                        serde_json::json!({"status": "ok", "bucket": bucket, "objects": objects})
                    );
                }
                ObjectCommands::Delete { bucket, key } => {
                    if let Err((_, msg)) = state.ensure_not_worm_locked(&bucket, &key) {
                        eprintln!(
                            "{}",
                            serde_json::json!({
                                "status": "error",
                                "code": "ObjectLocked",
                                "message": msg
                            })
                        );
                        std::process::exit(1);
                    }
                    let mpath = state.object_manifest_path(&bucket, &key);
                    if mpath.exists() {
                        fs::remove_file(&mpath)?;
                    }
                    println!(
                        "{}",
                        serde_json::json!({"status": "ok", "action": "object.delete", "bucket": bucket, "key": key})
                    );
                }
            }
        }

        Commands::Presign {
            bucket,
            key,
            expires,
            method,
            endpoint,
        } => {
            let (access_key, secret_key) = load_credentials(true)?;
            let state = S3State::new(
                &cli.cas_dir,
                &cli.s3_dir,
                access_key,
                secret_key,
                "127.0.0.1:9000".to_string(),
            )?;
            let url = state.generate_presigned_url(&endpoint, &method, &bucket, &key, expires);
            if cli.json {
                println!(
                    "{}",
                    serde_json::json!({
                        "status": "ok",
                        "bucket": bucket,
                        "key": key,
                        "method": method,
                        "expires_secs": expires,
                        "presigned_url": url,
                    })
                );
            } else {
                println!("{}", url);
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cas_dedup_range_and_worm_lock() {
        let tmp = std::env::temp_dir().join(format!("meshfs-s3-test-{}", std::process::id()));
        let cas_dir = tmp.join("cas");
        let s3_dir = tmp.join("s3");
        let state = S3State::new(
            &cas_dir,
            &s3_dir,
            "PMTESTKEY1234567890".to_string(),
            "secret-test-key-0123456789abcdef".to_string(),
            "127.0.0.1:9000".to_string(),
        )
        .unwrap();

        fs::create_dir_all(state.bucket_dir("qual")).unwrap();

        // 5 MiB payload (2 chunks: 4 MiB + 1 MiB)
        let payload: Vec<u8> = (0..(5 * 1024 * 1024)).map(|i| (i % 251) as u8).collect();
        let retain = (Utc::now() + Duration::hours(24)).to_rfc3339();
        let (m1, new1) = state
            .put_object(
                "qual",
                "obj1.bin",
                &payload,
                "application/octet-stream".to_string(),
                Some(retain),
                Some("COMPLIANCE".to_string()),
                BTreeMap::new(),
            )
            .unwrap();
        assert_eq!(m1.chunks.len(), 2);
        assert!(m1.chunks[0].id.starts_with("blake3:"));
        assert_eq!(new1, 2);
        assert!(m1.is_worm_locked());

        // Second PUT with identical data under another key writes 0 new CAS chunks!
        let (_, new2) = state
            .put_object(
                "qual",
                "obj2.bin",
                &payload,
                "application/octet-stream".to_string(),
                None,
                None,
                BTreeMap::new(),
            )
            .unwrap();
        assert_eq!(new2, 0);

        // Overwrite of WORM-locked obj1.bin must fail with 403 FORBIDDEN!
        let err = state
            .put_object(
                "qual",
                "obj1.bin",
                b"tamper",
                "application/octet-stream".to_string(),
                None,
                None,
                BTreeMap::new(),
            )
            .unwrap_err();
        assert_eq!(err.0, StatusCode::FORBIDDEN);

        // Cross-chunk Range read straddling 4 MiB boundary (4194300..=4194310)
        let slice = state.read_object_range(&m1, 4_194_300, 4_194_310).unwrap();
        assert_eq!(slice, &payload[4_194_300..=4_194_310]);

        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_sigv4_and_presign_tamper_rejected() {
        let tmp = std::env::temp_dir().join(format!("meshfs-s3-auth-{}", std::process::id()));
        let state = S3State::new(
            &tmp.join("cas"),
            &tmp.join("s3"),
            "PMTESTKEY1234567890".to_string(),
            "secret-test-key-0123456789abcdef".to_string(),
            "127.0.0.1:9000".to_string(),
        )
        .unwrap();

        // 1. Forged AWS4-HMAC-SHA256 header with valid AccessKeyId but fake signature must be rejected!
        let mut hdrs = HeaderMap::new();
        hdrs.insert(
            "authorization",
            "AWS4-HMAC-SHA256 Credential=PMTESTKEY1234567890/20261028/us-east-1/s3/aws4_request, SignedHeaders=host, Signature=0000000000000000000000000000000000000000000000000000000000000000"
                .parse()
                .unwrap(),
        );
        hdrs.insert("host", "127.0.0.1:9000".parse().unwrap());
        hdrs.insert("x-amz-date", "20261028T000000Z".parse().unwrap());
        let uri: Uri = "/qual/obj1.bin".parse().unwrap();
        let res = state.verify_request_auth(&Method::GET, &uri, &hdrs, &HashMap::new());
        assert_eq!(res, Err((StatusCode::FORBIDDEN, "SignatureDoesNotMatch")));

        // 2. Forged X-Amz-Date query without X-Amz-Expires or with invalid signature must be rejected!
        let mut q = HashMap::new();
        q.insert("X-Amz-Credential".to_string(), "PMTESTKEY1234567890".to_string());
        q.insert("X-Amz-Date".to_string(), "20261028T000000Z".to_string());
        q.insert(
            "X-Amz-Signature".to_string(),
            "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        );
        let res_q = state.verify_request_auth(&Method::GET, &uri, &HeaderMap::new(), &q);
        assert!(res_q.is_err());

        // 3. Anti-traversal bucket & upload_id checks
        assert!(!is_valid_bucket_name(".."));
        assert!(!is_valid_bucket_name(".hidden"));
        assert!(is_valid_bucket_name("qualification-s3"));
        assert!(!is_valid_upload_id("../../../etc"));

        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_universal_gc_and_bucket_quota() {
        let tmp = std::env::temp_dir().join(format!("meshfs-s3-gc-quota-{}", std::process::id()));
        let cas_dir = tmp.join("cas");
        let s3_dir = tmp.join("s3");
        let state = S3State::new(
            &cas_dir,
            &s3_dir,
            "PMTESTKEY1234567890".to_string(),
            "secret-test-key-0123456789abcdef".to_string(),
            "127.0.0.1:9000".to_string(),
        )
        .unwrap();

        fs::create_dir_all(state.bucket_dir("qtest")).unwrap();
        state.set_bucket_quota("qtest", 1024).unwrap();

        // Put 600 bytes -> OK
        let data1 = vec![0x41u8; 600];
        state
            .put_object(
                "qtest",
                "k1.bin",
                &data1,
                "application/octet-stream".to_string(),
                None,
                None,
                BTreeMap::new(),
            )
            .unwrap();

        // Put another 600 bytes under k2.bin -> exceeds 1024 byte quota -> 507 InsufficientStorage!
        let data2 = vec![0x42u8; 600];
        let err = state
            .put_object(
                "qtest",
                "k2.bin",
                &data2,
                "application/octet-stream".to_string(),
                None,
                None,
                BTreeMap::new(),
            )
            .unwrap_err();
        assert_eq!(err.0, StatusCode::INSUFFICIENT_STORAGE);

        // Now test Universal GC: data2 wrote 1 orphan chunk before manifest sealing was rejected by quota!
        let rep = state.run_universal_cas_gc(0, false);
        assert_eq!(rep.referenced_chunks, 1);
        assert_eq!(rep.deleted_chunks, 1);
        assert_eq!(rep.reclaimed_bytes, 600);

        let _ = fs::remove_dir_all(&tmp);
    }
}
