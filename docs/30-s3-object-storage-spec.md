# MRK S3-Compatible Object Storage Module — Engineering Spec (research draft)

Date: 2026-11-08 · Status: research / pre-ADR · Proposed doc number: `docs/30-s3-object-storage-spec.md`
Scope: a clean-room, native module, `object-s3`, that implements the Amazon S3 REST protocol inside the MRK appliance (one image, supervisord, FastAPI control plane, PGlite/PostgreSQL, `/data` bind mount, optional Host Agent).

Read first: `README.md`, `docs/20` (modular appliance, hostname routes), `docs/23` (native-engine ADR), `docs/26` (OCI spec, which this document follows in style and reuses for streaming and GC), `docs/27` (everything configurable), `docs/28`/`docs/29` (Host Agent, Gates 16–19, S6 backup).

Legend: **[V]** verified against a source during this research. **[M]** from memory of the AWS docs; re-verify against the pinned AWS API reference while implementing. **[?]** uncertain; needs a PoC or a black-box test.

---

## 0. Executive summary

- **What we build.** Module `object-s3`. It runs as its own supervisord program, `s3-engine` (uvicorn + uvloop + httptools on `127.0.0.1:9100`). The Edge Gateway publishes it on `s3.<domain>` (path-style), `*.s3.<domain>` (virtual-hosted), and per-bucket custom domains or website hosts. Every line is our own Python. **No MinIO, Garage, SeaweedFS, Ceph RGW, Zenko or LocalStack code or binaries.** We use permissive libraries only: `cryptography`, `awscrt` (Apache-2.0, for CRC32C and CRC64NVME), and `defusedxml` (PSF), or a hand-written XML parser with an allowlist.
- **Two bucket kinds.** (a) **Managed buckets**: content files under `/data/modules/s3/buckets/<bucket-id>/`, plus an object index. (b) **Linked-folder buckets**: a host directory that the user bind-mounts into the container at `/mnt/links/<name>`. In these, objects *are* plain files (`key a/b/c.txt` ↔ `a/b/c.txt`), so files added over SSH or by another container show up on their own.
- **Primary design target: be Dokploy's backup destination.** Dokploy runs `rclone rcat … --s3-force-path-style --s3-no-check-bucket --s3-endpoint=… --s3-region=…` and pipes the dump straight in **[V]**. `rcat` of a stream of unknown size uses **multipart upload** (rclone chunk default 5 MiB), so multipart, ListObjects (retention), DeleteObject, HeadObject and path-style addressing are all MVP-critical.
- **New AWS SDKs break naive S3 clones.** Since early 2025, the AWS SDKs and CLI v2 send flexible checksums by default: boto3 uses CRC32 and **CLI v2 uses CRC64NVME** **[V]**. Over HTTPS they upload with `Content-Encoding: aws-chunked` + `x-amz-content-sha256: STREAMING-UNSIGNED-PAYLOAD-TRAILER` and a trailing `x-amz-checksum-*` header. The MVP must decode aws-chunked (signed and unsigned, with or without trailer) and verify CRC32, CRC32C, CRC64NVME, SHA1 and SHA256.
- **Metadata placement (key decision).** Control data stays in PGlite/PostgreSQL (`s3_*` tables): buckets, identities, keys, policies, quotas, audit. The **per-object index lives in a per-bucket SQLite (WAL) file owned by `s3-engine`**. PGlite runs `--max-connections=1` (see `supervisord.conf`), and it would otherwise sit on the hot path of every PUT, LIST and HEAD. External PostgreSQL mode may optionally move the index into Postgres (P2).
- **Python is adequate.** The users are a solo DevOps person: backups, app uploads, static assets. Expected throughput is ~150–400 MB/s per stream for PUT (MD5 + CRC bound) and disk/NIC speed for GET with gateway sendfile offload. A native data plane is not justified for MVP (§8).
- **Effort.** MVP ≈ 9–11 engineer-weeks, P1 ≈ 7–9, P2 ≈ 8–10 (§10).

---

## 1. S3 API surface

### 1.1 Request routing and addressing

| Style | Example | Bucket from | Notes |
|---|---|---|---|
| Path-style | `https://s3.example.com/backups/db/2026.sql.gz` | first path segment | Dokploy, rclone (`force_path_style`), mc, restic, s3cmd (when configured). **MVP default.** |
| Virtual-hosted | `https://backups.s3.example.com/db/2026.sql.gz` | leftmost label of Host minus the configured suffix | Default for boto3/aws-cli when `addressing_style=auto` and the endpoint is a custom DNS name **[?]**. Needs wildcard DNS `*.s3.<domain>` and a wildcard TLS cert. MVP supports it **if** the wildcard route exists; otherwise the setup snippets force path-style. |
| Custom domain | `https://files.example.com/logo.png` → bucket `site` | route registry `(hostname → bucket_id, mode=api|website)` | P1. A website-mode host serves anonymous GETs, index/error documents and no S3 API. API-mode hosts accept the full API with the bucket implied. |

- The service endpoint `GET /` on `s3.<domain>` is ListBuckets.
- Hostname resolution comes **only** from the gateway's route snapshot (doc 20 §3). We never trust a raw Host header from untrusted peers.
- Bucket names with dots (`a.b`) break wildcard TLS in virtual-hosted style. They are allowed, but the panel shows a warning, and clients for such buckets are forced to path-style.
- **Single ASGI catch-all route.** FastAPI path params cannot express S3 subresources cleanly. We parse `(bucket, key, query-subresources)` ourselves, the same approach as docs/26 §1.1. The raw path is read from `scope["raw_path"]` and **must not** be the decoded `scope["path"]`. This is essential for SigV4 canonicalization and for keys containing `%2F`, `+` and similar.
- **Region.** `MRK_S3_REGION`, default `us-east-1`, configurable in the panel. SigV4 credential scope must match the configured region. Option `accept_any_region` (default **on**) accepts any region string in the scope and computes the signature with the client's stated region. This helps tools hard-coded to `us-east-1` or to `ir-thr-at1` (Arvan-style) configs. `GetBucketLocation` returns `<LocationConstraint/>` (empty) for us-east-1, or the configured region.

### 1.2 Bucket naming

Enforce the AWS rules for general-purpose buckets **[M]**:
- 3–63 characters, `[a-z0-9.-]`, starting and ending with a letter or digit;
- no `..`, not IP-shaped;
- no `xn--` prefix and no `-s3alias` / `--ol-s3` suffix.

Names are unique per appliance, because there is a single namespace. Our extra rule: reserved names `mrk`, `admin`, `api`, `www`, `_` are rejected.

### 1.3 Operation matrix

Phases: **MVP** = must ship for Gate S3-1 (Dokploy, rclone, restic, aws-cli, boto3, mc work). **P1** = full "powerful service" level. **P2** = enterprise features.

#### Service / bucket

| Operation | HTTP | Phase | Notes |
|---|---|---|---|
| ListBuckets | `GET /` | MVP | Only buckets the identity has `s3:ListAllMyBuckets` for, filtered further by any bucket-level allow. `Owner` = our canonical ID (hex of the identity UUID). P1: `max-buckets`, `continuation-token`, `prefix`, `bucket-region` (the 2024 additions) **[M]**. |
| CreateBucket | `PUT /{b}` | MVP | Optional `CreateBucketConfiguration/LocationConstraint` must equal our region or be absent. Existing bucket you own → `BucketAlreadyOwnedByYou` (409). Owned by someone else → `BucketAlreadyExists` (409). Headers `x-amz-acl` (canned) and `x-amz-bucket-object-lock-enabled` (P2). Linked-folder buckets are created **only from the panel**, never via the API. |
| DeleteBucket | `DELETE /{b}` | MVP | `BucketNotEmpty` (409) if any object or in-progress multipart upload exists. Linked buckets: deleting the bucket detaches the link and never deletes the files. |
| HeadBucket | `HEAD /{b}` | MVP | 200 + `x-amz-bucket-region`. 404/403 with no body. rclone uses it unless `--s3-no-check-bucket`. |
| GetBucketLocation | `GET /{b}?location` | MVP | See §1.1. |
| ListObjectsV2 | `GET /{b}?list-type=2` | MVP | §1.4 |
| ListObjects (V1) | `GET /{b}` | MVP | `marker`, `NextMarker` (only when a delimiter is given, per AWS **[M]**; we always emit it for safety). rclone with provider `Other` may default to V1 **[?]**. |
| ListObjectVersions | `GET /{b}?versions` | P1 (mandatory once versioning ships) | Unversioned buckets return every object with `VersionId=null`. Some tools (restic? rclone `--s3-versions`) call it **[?]**. |
| Get/PutBucketVersioning | `?versioning` | Get MVP (returns empty config), Put P1 | Status `Enabled`/`Suspended`. `MFADelete` is rejected. |
| Get/Put/DeleteBucketCors | `?cors` | P1 | §1.9 |
| Get/Put/DeleteBucketPolicy, GetBucketPolicyStatus | `?policy`, `?policyStatus` | P1 (MVP gets canned public-read via the panel) | §2.5 |
| Get/PutBucketAcl | `?acl` | MVP read-only (FULL_CONTROL owner), Put canned only, P1 | Grants other than canned → `NotImplemented` (501). |
| Get/Put/DeleteBucketLifecycle(Configuration) | `?lifecycle` | P1 | §1.10 |
| Get/Put/DeleteBucketWebsite | `?website` | P1 | §4.3 |
| Get/Put/DeleteBucketTagging | `?tagging` | P1 | ≤ 50 tags |
| Get/PutBucketEncryption | `?encryption` | Get MVP (returns `ServerSideEncryptionConfigurationNotFoundError` or SSE-S3 if global SSE is on), Put P2 | |
| Get/PutObjectLockConfiguration | `?object-lock` | P2 | |
| GetBucketOwnershipControls, PublicAccessBlock | `?ownershipControls`, `?publicAccessBlock` | P1 (stub `BucketOwnerEnforced`; PAB real) | PublicAccessBlock is our master switch against accidental public exposure. |
| Notifications / replication / logging / analytics / inventory / intelligent-tiering / accelerate / requestPayment | | out of scope | `NotImplemented`. GetBucketRequestPayment returns `BucketOwner` and GetBucketAccelerate returns empty, because some GUIs probe them **[?]** (Cyberduck). |

#### Object

| Operation | HTTP | Phase | Notes |
|---|---|---|---|
| PutObject | `PUT /{b}/{k}` | MVP | Streaming body. `Content-MD5` verify → `BadDigest`. `x-amz-checksum-*` verify. `x-amz-meta-*` (≤ 2 KB total for user metadata, per AWS **[M]**). `Content-Type/Encoding/Disposition/Language`, `Cache-Control`, `Expires`, `x-amz-tagging` (url-encoded query), `x-amz-storage-class` (accept `STANDARD`; anything else is stored, echoed and ignored, or rejected with `InvalidStorageClass`, configurable). Conditional writes: `If-None-Match: *` (create-only; AWS added it in 2024 **[M]**) and `If-Match: <etag>` (P1) → `PreconditionFailed` 412 / `ConditionalRequestConflict` 409. Max single PUT 5 GiB (AWS) → `EntityTooLarge`. Our cap is configurable: `max_single_put_bytes`, default 5 GiB. |
| GetObject | `GET /{b}/{k}` | MVP | Range (§1.6), conditionals (§1.7), `partNumber=N` (P1), response-header overrides `response-content-type`, `response-content-disposition`, `response-cache-control`, `response-expires`, `response-content-language`, `response-content-encoding` (only on signed or presigned requests, not anonymous **[M]**), `x-amz-checksum-mode: ENABLED` → return the stored checksum headers. |
| HeadObject | `HEAD /{b}/{k}` | MVP | Same headers as GET, no body. Errors carry no body (status only); 404 for a missing key **when the caller has ListBucket**, otherwise 403 (AWS semantics, avoids enumeration). |
| DeleteObject | `DELETE /{b}/{k}` | MVP | Always 204, even if the key is missing. Versioned (P1): creates a delete marker and returns `x-amz-delete-marker`, `x-amz-version-id`. |
| DeleteObjects | `POST /{b}?delete` | MVP | ≤ 1000 keys → `MalformedXML` if more. `Content-MD5` **or** an `x-amz-checksum-*` header is required (AWS relaxed the MD5 requirement in 2025 for new SDKs that send CRC instead **[V-ish]**: accept either; reject when both are missing → `InvalidRequest`). `<Quiet>true</Quiet>` returns errors only. Per-key `<Error><Key/><Code/><Message/></Error>`. |
| CopyObject | `PUT /{b}/{k}` + `x-amz-copy-source: /src-bucket/src-key[?versionId=]` (url-encoded) | MVP | `x-amz-metadata-directive: COPY|REPLACE` (copy onto itself requires REPLACE, else `InvalidRequest` "…without changing…"). `x-amz-tagging-directive`. `x-amz-copy-source-if-match`, `-if-none-match`, `-if-modified-since`, `-if-unmodified-since`. Response body is `<CopyObjectResult><ETag/><LastModified/>` + checksum fields. Managed→managed in the same filesystem: **hard link or reflink** when possible (no data copy; ETag preserved), else streamed copy. Linked buckets: `copy_file_range`/`os.sendfile` via `shutil.copyfile`. Max 5 GiB source for a single copy (AWS) → `InvalidRequest`; larger sources use UploadPartCopy. Needs `s3:GetObject` on the source and `s3:PutObject` on the destination. |
| GetObjectTagging / PutObjectTagging / DeleteObjectTagging | `?tagging` | P1 | ≤ 10 tags, key ≤ 128 and value ≤ 256 Unicode characters. Lifecycle filters use tags. |
| GetObjectAttributes | `?attributes` | P1 | ETag, Checksum, ObjectParts, StorageClass, ObjectSize. New SDKs use it for multipart checksum validation **[?]**. |
| GetObjectAcl / PutObjectAcl | `?acl` | P1 (canned `private`/`public-read` only) | Default: ownership is BucketOwnerEnforced, so object ACLs are disabled and return `AccessControlListNotSupported` unless the bucket opts into ACLs. |
| Get/PutObjectRetention, Get/PutObjectLegalHold | | P2 | Object lock |
| RestoreObject, SelectObjectContent, WriteGetObjectResponse, rename (S3 Express RenameObject) | | out of scope | `NotImplemented` |
| POST Object (browser form upload) | `POST /{b}` multipart/form-data | P1 | §2.4 |
| OPTIONS preflight | `OPTIONS /{b}/{k}` | P1 | CORS §1.9 |

#### Multipart

| Operation | HTTP | Phase | Notes |
|---|---|---|---|
| CreateMultipartUpload | `POST /{b}/{k}?uploads` | MVP | Stores metadata, content headers, tagging, ACL and `x-amz-checksum-algorithm` (+ `x-amz-checksum-type: COMPOSITE|FULL_OBJECT`, 2025 **[M]**). UploadId = 128-bit random, base64url, bound to bucket+key+initiator. |
| UploadPart | `PUT /{b}/{k}?partNumber=N&uploadId=U` | MVP | N ∈ 1..10000 → `InvalidArgument`. Part ≤ 5 GiB. Re-uploading the same N replaces that part (last writer wins). Returns `ETag: "md5hex"` + checksum header. `Content-MD5` / checksum verified per part. |
| UploadPartCopy | `PUT …?partNumber&uploadId` + `x-amz-copy-source` [+ `x-amz-copy-source-range: bytes=a-b`] | MVP (rclone server-side copy of >5 GiB, mc) | Response `<CopyPartResult><ETag/><LastModified/>`. |
| CompleteMultipartUpload | `POST /{b}/{k}?uploadId=U` | MVP | Parts must be ascending → `InvalidPartOrder`. Each listed ETag must match a stored part → `InvalidPart`. Every part except the last must be ≥ 5 MiB → `EntityTooSmall` (min configurable, default 5 MiB to match AWS so client tests behave identically). Duplicate part numbers → `InvalidPartOrder`. **ETag** = `"` + hex(md5(concat(binary md5 of each part))) + `-` + N + `"`. Checksums: COMPOSITE = checksum of the concatenated part checksums + `-N`. FULL_OBJECT (CRC only) = combined CRC (CRC combine math, P1). The response is HTTP 200 **even if it fails later**: we send headers early and whitespace keepalives while assembling large uploads, then `<Error>` inside a 200 body. AWS does exactly this and SDKs handle it **[M]**. Idempotency: a repeated Complete with the same part list after success returns the same result if the object still matches (P1). |
| AbortMultipartUpload | `DELETE …?uploadId=U` | MVP | 204. Unknown → `NoSuchUpload` 404. |
| ListParts | `GET …?uploadId=U` | MVP | `max-parts` ≤ 1000, `part-number-marker`, `NextPartNumberMarker`, `IsTruncated`. Used by rclone/restic resume? **[?]**, by mc and by the SDK transfer managers. |
| ListMultipartUploads | `GET /{b}?uploads` | MVP | `prefix`, `delimiter`, `key-marker`, `upload-id-marker`, `max-uploads` ≤ 1000. |

**Assembly strategy (managed buckets):** parts are stored as separate files. Complete performs either (a) **logical assembly**: the object row stores the part list (`parts: [(file, size, offset)]`) and GET streams across part files. Complete is then O(1) and needs no copy, which avoids a 2× disk spike for a 50 GB DB dump. Or (b) **physical concatenation** using `copy_file_range` into one file. **Recommendation: (a) for managed buckets**. GET of `partNumber=N` and Range math map to parts naturally. Linked buckets must have a real file, so they use (b): concatenate into a temp file in the same directory, fsync, rename. A background compaction task can optionally convert (a) to a single file for objects < 1 GiB.

### 1.4 Listing semantics (the "folders")

- Keys are UTF-8 byte strings, sorted in **binary (UTF-8 byte) order** (AWS is lexicographic by UTF-8 bytes). SQLite with `BLOB` keys or `COLLATE BINARY` on TEXT matches this. PostgreSQL needs `COLLATE "C"`.
- `prefix` + `delimiter` (typically `/`): keys containing the delimiter after the prefix are rolled up into `<CommonPrefixes><Prefix>…/</Prefix>`. Each common prefix counts toward `max-keys` (≤ 1000, default 1000; values > 1000 are clamped to 1000).
- **Efficient rollup:** after emitting common prefix `p/`, seek to the first key `> p/` + `\xff…`. Concretely, seek `key >= p[:-1] + chr(ord('/')+1)` (i.e. `p` with the trailing delimiter byte incremented). This keeps a folder with 1M objects O(1) to skip. It must work for arbitrary delimiters (any string, not just `/`).
- V2: `continuation-token` is **opaque**. We use base64url(HMAC-signed JSON `{last_key, bucket_id, gen}`), so clients cannot forge cursors into other buckets. `start-after`, `fetch-owner` (default false in V2), `KeyCount`, `NextContinuationToken`.
- `encoding-type=url`: URL-encode `Key`, `Prefix`, `Delimiter`, `StartAfter`, `NextMarker` and `CommonPrefixes/Prefix` in responses. This is required for keys with control characters, which are not representable in XML 1.0. **Even without encoding-type=url, keys with chars invalid in XML 1.0** must be rejected at write time, or we always force escaping **[?]**. Decision: reject keys containing `\x00` and characters outside the XML 1.0 Char production unless bucket option `allow_xml_unsafe_keys` is set (AWS allows them; ceph s3-tests have a case).
- Response element order follows the AWS XML exactly: `Name, Prefix, (Marker|ContinuationToken), MaxKeys, Delimiter?, IsTruncated, Contents*, CommonPrefixes*, EncodingType?` **[M]**. Some strict parsers (older Java SDK) are order-sensitive **[?]**.
- Each `Contents` holds `Key, LastModified (ISO8601 ms Z), ETag (quoted), ChecksumAlgorithm?, ChecksumType?, Size, Owner?, StorageClass (STANDARD)`.
- **"Folder" objects:** zero-byte keys ending in `/` (created by the AWS console, Cyberduck and our own panel's "New folder"). In managed buckets they are ordinary index rows. Linked buckets: see §3.2.
- Consistency: AWS is strongly read-after-write consistent for PUT, DELETE and LIST since 2020. We provide this for managed buckets: the index commit happens before the response is sent. Linked buckets get it for writes made *through S3*. External writes appear after the next reconcile (§3.2).

### 1.5 ETag rules

| Case | ETag |
|---|---|
| Single PUT, no SSE or SSE-S3 | `"hex(md5(body))"` |
| Multipart | `"hex(md5(md5(p1)‖…‖md5(pN)))-N"` |
| CopyObject (single-part source) | Same as the source. Multipart source copied by CopyObject: AWS recomputes as single-part MD5 **[M]**. We do the same when we really copy, and keep the source ETag when we hard-link (documented deviation; clients only compare ETags for equality, not their derivation) **[?]**. |
| SSE-C / SSE-KMS (n/a) | not MD5 |
| Linked folder, file written outside S3 | `"<md5>"` if cached, else a **weak synthetic** `"<hex(sha256(inode,size,mtime_ns))[:32]>"`. 32 hex characters, so it looks like an MD5. Clients such as rclone check `md5 == ETag` for non-multipart objects and would then report a mismatch, so the linked bucket option `etag_mode=md5` (default for buckets < N GB) computes real MD5s lazily in the background and serves the synthetic tag until then (§3.2). |

rclone also stores `X-Amz-Meta-Md5chksum` for multipart uploads and checks it on download. Supporting user metadata covers this.

### 1.6 Range GET

- Single range `bytes=a-b`, `bytes=a-`, `bytes=-n` → 206 + `Content-Range: bytes a-b/total`. Unsatisfiable → 416 `InvalidRange` + `Content-Range: bytes */total`.
- Multi-range (`a-b,c-d`): AWS ignores it and returns the full object with 200 **[M]**. We do the same.
- `If-Range` is not supported by S3 **[M]**, so ignore it.
- A Range plus checksum-mode returns no full-object checksum for partial content.

### 1.7 Conditional requests (GET/HEAD and copy-source)

Evaluate in RFC 7232 order:
1. `If-Match` mismatch → 412 `PreconditionFailed`;
2. `If-Unmodified-Since` false (and no If-Match) → 412;
3. `If-None-Match` match → 304 (GET/HEAD);
4. `If-Modified-Since` not modified (and no If-None-Match) → 304.

AWS has a documented quirk: If-Match true + If-Unmodified-Since false → 200, and If-None-Match false + If-Modified-Since true → 304 **[M]**. Copy-source variants return 412 only. ETag comparison strips quotes and accepts `*`.

### 1.8 Errors (XML)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<Error><Code>NoSuchKey</Code><Message>The specified key does not exist.</Message>
<Key>a/b.txt</Key><BucketName>backups</BucketName><Resource>/backups/a/b.txt</Resource>
<RequestId>4442587FB7D0A2F9</RequestId><HostId>…</HostId></Error>
```
Headers: `x-amz-request-id`, `x-amz-id-2` (always, including success). `Content-Type: application/xml`. HEAD errors have no body.

| Code | HTTP | Used for |
|---|---|---|
| AccessDenied | 403 | policy deny, no permission, public access blocked |
| AccountProblem / AllAccessDisabled | 403 | disabled identity / suspended module |
| AuthorizationHeaderMalformed | 400 | bad Credential scope, wrong region (when strict) — body includes `<Region>` |
| AuthorizationQueryParametersError | 400 | presign param errors, expires > 7 d |
| BadDigest | 400 | Content-MD5 mismatch |
| BucketAlreadyExists / BucketAlreadyOwnedByYou | 409 | |
| BucketNotEmpty | 409 | |
| EntityTooLarge / EntityTooSmall | 400 | |
| ExpiredToken / AccessDenied "Request has expired" | 400/403 | presigned expiry (AWS returns 403 AccessDenied "Request has expired" **[M]**) |
| IncompleteBody | 400 | fewer bytes than Content-Length / decoded length |
| InternalError | 500 | |
| InvalidAccessKeyId | 403 | unknown or disabled key |
| InvalidArgument | 400 | bad partNumber, max-keys, header values |
| InvalidBucketName | 400 | |
| InvalidDigest | 400 | malformed Content-MD5 |
| InvalidPart / InvalidPartOrder | 400 | |
| InvalidRange | 416 | |
| InvalidRequest | 400 | misc (copy onto self, checksum missing) |
| InvalidObjectState | 403 | object lock / archived (P2) |
| InvalidStorageClass | 400 | |
| KeyTooLongError | 400 | key > 1024 UTF-8 bytes |
| MalformedXML / MalformedPolicy / MalformedPOSTRequest | 400 | |
| MetadataTooLarge | 400 | user metadata > 2 KB |
| MethodNotAllowed | 405 | |
| MissingContentLength | 411 | PUT without Content-Length and without aws-chunked/decoded-length |
| MissingSecurityHeader | 400 | |
| NoSuchBucket / NoSuchKey / NoSuchUpload / NoSuchVersion | 404 | |
| NoSuchBucketPolicy / NoSuchCORSConfiguration / NoSuchLifecycleConfiguration / NoSuchTagSet / NoSuchWebsiteConfiguration | 404 | |
| NotImplemented | 501 | unsupported subresource/header |
| PreconditionFailed | 412 | |
| ConditionalRequestConflict | 409 | concurrent conditional write |
| QuotaExceeded (our code; AWS has none) | 403 | per-bucket/user quota. Clients treat it as AccessDenied-like. Message text explains. |
| RequestTimeout | 400 | idle body read > N s |
| RequestTimeTooSkewed | 403 | > 15 min skew; body includes `RequestTime`, `ServerTime`, `MaxAllowedSkewMilliseconds` |
| SignatureDoesNotMatch | 403 | body includes `StringToSign`, `CanonicalRequest` **only** when debug is enabled for that key (AWS does include them **[M]**; we gate them behind a per-key debug toggle because they help users and leak little) |
| SlowDown | 503 | rate limit / PGlite backpressure, with `Retry-After` |
| XAmzContentSHA256Mismatch | 400 | payload hash mismatch |
| InvalidChunkSizeError / InvalidSignature (chunk) | 403/400 | aws-chunked errors |
| InvalidEncryptionAlgorithmError | 400 | |
| TooManyBuckets | 400 | configurable max buckets |

### 1.9 CORS (P1)

`PutBucketCors` XML holds `CORSRule{ID?, AllowedOrigin+, AllowedMethod+ (GET|PUT|POST|DELETE|HEAD), AllowedHeader*, ExposeHeader*, MaxAgeSeconds?}`, ≤ 100 rules, ≤ 64 KB.
- Matching: first rule whose origin (one `*` wildcard allowed per origin), method and every requested header match.
- Preflight `OPTIONS` without a matching rule → 403 `AccessForbidden`/`CORSResponse` **[M]**.
- Actual requests add `Access-Control-Allow-Origin` (echo the origin, or `*` if the rule is `*` and there are no credentials), `-Allow-Methods`, `-Expose-Headers` (always add `ETag`, because browser multipart uploads need it), `Vary: Origin`.
- The panel needs CORS on its own buckets for drag-and-drop uploads. The panel upload path uses **same-origin** proxying through the control plane by default (§5), so no bucket CORS is required for that.

### 1.10 Lifecycle (P1)

Supported elements:
- `Rule{ID, Status, Filter{Prefix|Tag|And{Prefix,Tag*,ObjectSizeGreaterThan,ObjectSizeLessThan}}}`;
- `Expiration{Days|Date|ExpiredObjectDeleteMarker}`, `NoncurrentVersionExpiration{NoncurrentDays, NewerNoncurrentVersions}`, `AbortIncompleteMultipartUpload{DaysAfterInitiation}`.

`Transition` → `NotImplemented` (single tier), or accepted and ignored behind a flag, because some tools push a full config **[?]**. The lifecycle worker runs as a `tasks.py` periodic job inside `s3-engine` (default daily at 03:00, configurable). It scans the index by prefix, deletes in batches of 1000, records audit summary rows (not one per object) and exposes metrics. A **dry-run preview** ("would delete 1,234 objects / 12 GB") is available in the panel.

Rule of thumb from AWS: the expiration time is rounded up to midnight UTC of the next day **[M]**.

### 1.11 Versioning (P1 core, P2 polish)

- Bucket states: `Unversioned` → `Enabled` ↔ `Suspended` (never back to unversioned).
- Index rows: `(bucket, key, version_id, is_latest, is_delete_marker, …)`. VersionId = 32-char base62 time-ordered ID (ULID-like), so the newest sorts first per key. Null version = `"null"`.
- Ops: GET/HEAD/DELETE with `versionId`; ListObjectVersions with `key-marker`/`version-id-marker`; CopyObject source `?versionId`.
- Storage: each version is its own content file, so linked buckets **cannot** be versioned (they reject PutBucketVersioning with `InvalidBucketState`, or store versions in a hidden `.mrk-versions/` area — P2 option, off by default).
- Quota counts all versions. The panel shows "noncurrent bytes".

### 1.12 Object Lock (P2)

Requires versioning, enabled at bucket creation. Modes GOVERNANCE/COMPLIANCE, retain-until date, legal hold. `x-amz-bypass-governance-retention` requires `s3:BypassGovernanceRetention`.

Value for the user: ransomware-resistant backups. "Compliance" here is only as strong as the box: root on the host can delete files. The panel must say so explicitly.

### 1.13 SSE (P2)

- **SSE-S3**: AES-256-GCM per object, data key wrapped by a module master key in SecretStore (or `MRK_S3_MASTER_KEY_FILE`). Chunked AEAD framing like MRKBKP2 (64 KiB records) so Range GET can decrypt from the containing record.
- `x-amz-server-side-encryption: AES256` is echoed. ETag stays the MD5 of the plaintext (AWS does this for SSE-S3 **[M]**).
- **SSE-C** (client-supplied key headers) — P2+, HTTPS only.
- SSE-KMS → `NotImplemented`.
- Not applicable to linked buckets (files must stay plain).

---

## 2. Authentication & identity

### 2.1 SigV4 header auth (MVP)

`Authorization: AWS4-HMAC-SHA256 Credential=AKID/YYYYMMDD/region/s3/aws4_request, SignedHeaders=h1;h2, Signature=hex`

Canonical request (implemented from the AWS docs; must be **byte-exact**):
```
METHOD\n
CanonicalURI\n          # S3: URI-encode each path segment ONCE (do not double-encode, do not normalize "." or "..", keep "//")
CanonicalQueryString\n  # sort by encoded name then value; encode with RFC3986 unreserved set; "=" for empty values; subresources like "uploads" become "uploads="
CanonicalHeaders\n      # lowercase names, trim + collapse inner whitespace of values, sorted, each "name:value\n"
SignedHeaders\n
HashedPayload           # value of x-amz-content-sha256
```
String to sign: `AWS4-HMAC-SHA256\n<x-amz-date>\n<scope>\n<hex(sha256(canonical_request))>`. Key derivation: `HMAC(HMAC(HMAC(HMAC("AWS4"+secret, date), region), "s3"), "aws4_request")`. Cache derived keys per `(akid, date, region)`, and cache the decrypted secret in process memory with a TTL (e.g. 5 min, wiped on key rotation).

Mandatory checks:
- `host` must be in SignedHeaders; so must `x-amz-content-sha256` and `x-amz-date`/`date` when present. Any `x-amz-*` header that is present but **unsigned** → reject (AWS requires all x-amz-* headers to be signed **[M]**). This closes a header-injection bypass.
- `x-amz-date` within ±15 min (configurable; `RequestTimeTooSkewed`). The scope date must equal the date part of x-amz-date.
- **The host value used is the Host header as received by the gateway.** The gateway must forward the original Host unchanged (or we reconstruct it from a trusted `X-Forwarded-Host`). This is the #1 cause of SignatureDoesNotMatch behind proxies. The gateway contract must list it.
- Compare with `hmac.compare_digest`.
- Payload hash modes:
  - `UNSIGNED-PAYLOAD`: allowed (default on; per-key option to require signed payloads over plain HTTP).
  - Hex sha256: verify while streaming. On mismatch, **delete the temp file and reject** (`XAmzContentSHA256Mismatch`) before commit.
  - `STREAMING-*` (§2.2).
  - `x-amz-content-sha256` missing in header auth → AWS rejects (`InvalidRequest` "Missing required header") **[M]**. Some old clients omit it, so make this a compat flag (default: require).
- `Content-Length` must be signed if present? No. Only verify that the headers listed are present.

### 2.2 Streaming / chunked uploads (MVP)

`Content-Encoding: aws-chunked` (possibly combined: `aws-chunked,gzip` — strip `aws-chunked` and store the rest). `x-amz-decoded-content-length` gives the real size. `Content-Length` is the encoded length (may be absent with HTTP chunked transfer).

| x-amz-content-sha256 | Chunk line | Trailer | Who sends it |
|---|---|---|---|
| `STREAMING-AWS4-HMAC-SHA256-PAYLOAD` | `hex;chunk-signature=<64hex>\r\n<data>\r\n` … `0;chunk-signature=…\r\n\r\n` | none | aws-sdk-java v1, older SDKs over HTTP, minio-go (mc) over HTTP |
| `STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER` | same | `x-amz-checksum-xxx:b64\r\nx-amz-trailer-signature:<64hex>\r\n\r\n` | SDKs over **plain HTTP** with checksums |
| `STREAMING-UNSIGNED-PAYLOAD-TRAILER` | `hex\r\n<data>\r\n` … `0\r\n` | `x-amz-checksum-xxx:b64\r\n\r\n` | **boto3 ≥ 1.36 / CLI v2 / JS v3 / Java v2 ≥ 2.30 over HTTPS (default)** **[V]** |
| `STREAMING-ECDSA-P256-SHA256-PAYLOAD[-TRAILER]` | SigV4a | | out of scope → `NotImplemented` |

Chunk string-to-sign: `AWS4-HMAC-SHA256-PAYLOAD\n<date>\n<scope>\n<prev-sig>\n<sha256("")>\n<hex sha256(chunk)>`. The seed is the header signature. Trailer: `AWS4-HMAC-SHA256-TRAILER\n<date>\n<scope>\n<last-chunk-sig>\n<hex sha256(canonical trailer "name:value\n")>` **[V via secondary summary; re-verify]**.

Decoder: an incremental state machine over `request.stream()`. It enforces:
- chunk-size line ≤ 4 KiB;
- chunk size ≤ 16 MiB (configurable);
- total decoded bytes == `x-amz-decoded-content-length` → `IncompleteBody`;
- trailer names ⊆ the `x-amz-trailer` header;
- trailer size ≤ 4 KiB.

**Never buffer the whole body.** The data passed to the writer and hasher is only the decoded chunk payload. With signed chunks, per-chunk SHA-256 adds CPU (§8), and **the data must not be committed until each chunk's signature is verified**. Because we write to a temp file and commit only at the end, a mid-stream signature failure simply drops the temp file.

### 2.3 Presigned URLs (query SigV4) (MVP)

Query params: `X-Amz-Algorithm=AWS4-HMAC-SHA256`, `X-Amz-Credential`, `X-Amz-Date`, `X-Amz-Expires` (1..604800 s, i.e. ≤ 7 days → `AuthorizationQueryParametersError`), `X-Amz-SignedHeaders`, `X-Amz-Signature`, optional `X-Amz-Security-Token`.
- Canonical query excludes `X-Amz-Signature`. The payload hash is `UNSIGNED-PAYLOAD`.
- Expired → 403 AccessDenied "Request has expired".
- Presigned URLs are evaluated as the *signing identity* at request time. Revoking the key or reducing the policy kills outstanding links. This is the main "revoke share link" mechanism.
- **Panel share links** are presigned by a per-user internal key (`svc-share-<user>`). Each share is recorded in `s3_shares` (id, bucket, key, expires, created_by) and can be revoked individually: we include a custom signed query param `x-mrk-share=<id>`, check it against the table, and refuse it once revoked. Because it is in the signed query, it cannot be stripped.
- Public endpoint: presigned URLs (panel, `mrk` CLI, API) are built from the **configured public endpoint** of the bucket route (path-style `https://s3.<domain>/b/k` or virtual-hosted, per setting), never from the panel's Host.
- Panel: expiry presets 1 h / 1 d / 7 d plus custom ≤ 7 d. Longer "permanent" links mean a public-read object or a website route instead (UI explains).

### 2.4 POST policy (browser form uploads) (P1)

`multipart/form-data` fields `key` (may contain `${filename}`), `policy` (base64 JSON `{expiration, conditions:[…]}`), `x-amz-algorithm`, `x-amz-credential`, `x-amz-date`, `x-amz-signature`, `success_action_status|redirect`, `Content-Type`, `x-amz-meta-*`, `acl`, and `file` (must be the last field).
- Signature = HMAC(signingKey, base64 policy).
- Conditions: `{"bucket":…}`, `["eq"|"starts-with", "$field", value]`, `["content-length-range", min, max]`. Any non-file form field not covered by a condition → `AccessDenied` (except `x-amz-signature`, `file`, `policy`, `x-ignore-*`).
- Streaming multipart parser: use `python-multipart` (Apache-2.0, already a Starlette optional dependency), with the field section capped at 20 KB and the file streamed directly to the temp file.

### 2.5 Identities, keys, policies

**Model (S3 identities are separate from panel users but owned by them):**

```
s3_identity(id uuid, kind user|service|share-internal, name, owner_user_id → core users,
            status active|disabled, quota_bytes?, quota_objects?, created_at, last_used_at)
s3_access_key(akid "MRK…" 20 chars [A-Z0-9], identity_id, secret_ref → SecretStore, status,
              created_at, expires_at?, last_used_at, last_used_ip, description)
s3_group(id, name)  s3_group_member(group_id, identity_id)
s3_policy(id, name, document jsonb, managed bool)   # managed = built-in templates
s3_attachment(policy_id, principal_type identity|group, principal_id)
s3_bucket(id, name, kind managed|linked, owner_identity_id, region, versioning, object_lock,
          public_access_block jsonb, policy jsonb?, cors jsonb?, lifecycle jsonb?, website jsonb?,
          quota_bytes?, quota_objects?, link_root?, link_mode ro|rw, link_options jsonb, created_at)
s3_route(hostname, bucket_id, mode api|website)  # also registered in the core route registry (doc 20)
s3_share(id, bucket_id, key, expires_at, created_by, revoked_at)
```

- **Secret storage.** SigV4 needs the plaintext secret. Store it with the existing `SecretStore` (AES-256-GCM, reference as AAD, key at `MRK_UPSTREAM_SECRET_KEY_FILE` or the generated key). Recommendation: a **separate store file** (`/data/control-plane/s3-secrets.json`, or a module-specific `SecretStore(root=/data/modules/s3/secrets)`). The current store rewrites one JSON file per change, which is fine for hundreds of keys and not for 10k; P2 moves it into a DB table with the same envelope. Generate secrets of 40 chars from `secrets.token_urlsafe` restricted to `[A-Za-z0-9+/]`, matching the AWS look. **Show once** in the panel; afterwards only the AKID and "last used" are shown.
- `s3-engine` reads secrets via a local, read-only interface: the same key file mounted for the engine user, or a control-plane internal endpoint over loopback with a service token. Recommendation: the engine opens the SecretStore directly in read-only mode. The control plane is the only writer and signals changes through a `generation` counter row in PGlite that the engine polls every 2 s (or via a loopback notify call).
- **Key rotation.** Each identity can hold up to 2 active keys (AWS pattern): create new → switch clients → disable old → delete. Optional `expires_at`. Last-used tracking happens in memory, flushed to DB once a minute (no per-request write).
- **Root/owner.** The MRK owner gets a bootstrap S3 identity `mrk-admin` with policy `S3FullAccess`, created on module enable. Its key is shown once. No environment-variable root key like `MINIO_ROOT_USER`; optional `MRK_S3_BOOTSTRAP_KEY_FILE` for automation.

**Panel RBAC (who may manage S3 in the panel)**, following the `<module>:<resource>:<action>` convention from `auth.py`/doc 29:

| Permission | owner | admin | operator | developer | viewer |
|---|---|---|---|---|---|
| `s3:bucket:read` (list, usage, browse metadata) | ✓ | ✓ | ✓ | ✓ (own) | ✓ |
| `s3:bucket:write` (create/delete/config) | ✓ | ✓ | – | own buckets | – |
| `s3:object:read` (browse/download in panel) | ✓ | ✓ | ✓ | own | – |
| `s3:object:write` (upload/delete/rename in panel) | ✓ | ✓ | ✓ | own | – |
| `s3:identity:write` (users/keys/policies) | ✓ | ✓ | – | own service keys | – |
| `s3:link:write` (linked folders — touches host files) | ✓ | – | – | – | – |
| `s3:public:write` (make bucket public, website, custom domain) | ✓ | ✓ | – | – | – |

The panel file browser acts **as the panel user** mapped to an internal S3 identity: permission check in the control plane → signed internal call to `s3-engine` with `X-MRK-Act-As`. The panel user's RBAC is the authority there. External S3 clients are only authorized by S3 policies. "own" = the bucket's `owner_identity.owner_user_id == user`.

**Policy language (subset of IAM/bucket policy), our own evaluator:**

```json
{"Version":"2012-10-17","Statement":[
 {"Sid":"RW","Effect":"Allow","Action":["s3:GetObject","s3:PutObject","s3:DeleteObject"],
  "Resource":["arn:aws:s3:::backups/dokploy/*"]},
 {"Effect":"Allow","Action":"s3:ListBucket","Resource":"arn:aws:s3:::backups",
  "Condition":{"StringLike":{"s3:prefix":["dokploy/*","dokploy/"]}}},
 {"Effect":"Deny","Action":"s3:*","Resource":"arn:aws:s3:::backups/*",
  "Condition":{"Bool":{"aws:SecureTransport":"false"}}}]}
```

- Elements: `Effect`, `Action`/`NotAction` (with `*` and `?` wildcards; the action list follows AWS names), `Resource`/`NotResource` (`arn:aws:s3:::bucket`, `arn:aws:s3:::bucket/keyglob`; also accept `arn:mrk:s3:::` as an alias), `Principal` (bucket policies only: `"*"`, `{"AWS":["arn:aws:iam:::user/<name>","<akid-owner-id>"]}`), `Condition`.
- Condition operators: `StringEquals`/`NotEquals`/`Like`/`NotLike`, `IpAddress`/`NotIpAddress`, `Bool`, `DateLessThan`/`GreaterThan`, `NumericLessThan`/…, `Null`, and the `ForAnyValue:`/`ForAllValues:` prefixes for tag keys (P2).
- Keys: `aws:SourceIp` (the client IP from the gateway's trusted forwarded header), `aws:SecureTransport`, `aws:CurrentTime`, `aws:username`, `aws:UserAgent`, `aws:Referer`, `s3:prefix`, `s3:delimiter`, `s3:max-keys`, `s3:x-amz-acl`, `s3:ExistingObjectTag/<k>` (P2), `s3:RequestObjectTag/<k>` (P2), `s3:signatureAge`, `s3:authType` (REST-HEADER|REST-QUERY-STRING|POST), `s3:x-amz-content-sha256`.
- Policy variables `${aws:username}` (enables a "home folder per user" template).
- Evaluation: explicit Deny wins > explicit Allow (identity policies ∪ group policies ∪ bucket policy) > implicit deny. Bucket owner is **not** implicitly allowed (unlike AWS same-account semantics); the bootstrap admin has an explicit `s3:*`. That makes it simpler and safer.
- Action mapping table: request → action(s), e.g. CopyObject = `s3:PutObject` on dest + `s3:GetObject` on source; UploadPart = `s3:PutObject`; ListParts = `s3:ListMultipartUploadParts`; HEAD object = `s3:GetObject`; ListObjectsV2 = `s3:ListBucket`; GetObjectTagging = `s3:GetObjectTagging`…
- Validation on save: JSON schema + action/ARN/condition-key allowlist + max 20 KB (bucket policy, AWS limit) / 6 KB (identity, AWS limit for user inline policy is 2 KB; we allow more) → `MalformedPolicy` with a precise message. The panel shows a **"policy simulator"** (P1): pick identity + action + key → Allow/Deny + matching statement.

**Built-in templates (Simple mode):** `ReadOnly(bucket[, prefix])`, `ReadWrite(bucket[, prefix])`, `WriteOnly/Dropbox(bucket, prefix)` (PutObject only, good for backup agents — they cannot delete history; note: rclone/restic retention needs Delete/List), `BackupClient(bucket, prefix)` (= Get/Put/List/Delete + multipart, the Dokploy template), `BucketAdmin(bucket)`, `S3FullAccess`.

**Service accounts:** identity `kind=service`, owned by a panel user, may only receive policies that are a **subset** of the owner's effective S3 permissions (checked at attach time by evaluating the intersection — simplest: service policy is evaluated AND owner's policies are evaluated; both must Allow). Used for Dokploy, CI, apps.

**Per-identity / per-bucket quotas:** `quota_bytes`, `quota_objects`, checked at PUT/Complete with the declared length (`Content-Length` / `x-amz-decoded-content-length`; for unknown length, checked progressively while streaming). Counters are kept in memory per bucket and flushed periodically; the authoritative value is recomputed nightly. Soft quota warning at 80% → notification center (S5). Exceeding → 403 `QuotaExceeded`.

**SigV2: decision — not supported (MVP and P1).** Every listed client supports V4 by default (s3cmd needs `signature_v2 = False`, default since 2.x **[M]**; WinSCP and Cyberduck use V4). V2 is HMAC-SHA1, deprecated by AWS since 2020, and expands the auth attack surface. Return `InvalidRequest` "Please use AWS4-HMAC-SHA256" for `Authorization: AWS ak:sig` and V2 query `Signature=`. P2 flag only if a real user hits a legacy client.

**Anonymous requests:** allowed only if the bucket policy/canned ACL grants `Principal:"*"` **and** PublicAccessBlock (bucket + global) permits it. The global switch "Allow public buckets" defaults to **off**.

---

## 3. Storage design

### 3.1 Managed buckets

```
/data/modules/s3/
├─ meta/
│  ├─ <bucket-id>.sqlite          # object index (WAL), owned by s3-engine
│  └─ uploads.sqlite              # multipart state (could be per bucket; one file is simpler)
├─ buckets/<bucket-id>/
│  ├─ objects/ab/cd/<object-uuid>          # content file; name is NOT the key
│  └─ parts/<upload-id>/<part-number>.<uuid>
├─ tmp/<bucket-id>/<uuid>.part    # in-flight PUT bodies (same filesystem as objects for rename)
├─ trash/                         # deferred deletes (GC)
└─ secrets/ (optional, see §2.5)
```

- **Content files are named by a random UUID, never by the key.** Keys never touch the filesystem in managed buckets, so path traversal is impossible by construction, and keys of up to 1024 bytes with any characters are fine.
- Not content-addressed (unlike OCI). S3 objects are mutable by key, dedup is rare and costly (we need the MD5 anyway, but SHA-256 would add 25% CPU). P2 option: hash-based dedup for identical content (`hardlink if sha256 equal`).
- **Object index row:** `(key BLOB PRIMARY KEY, version_id, size, etag, last_modified_ns, content_type, content_encoding, content_disposition, cache_control, content_language, expires, user_meta JSON, tags JSON, checksum_algo, checksum_type, checksum_value, part_layout JSON?, storage_path, sse JSON?, acl, owner_identity)` — `WITHOUT ROWID` table keyed by key for range scans. Versioned buckets: PK `(key, version_ord DESC)`.

**Why per-bucket SQLite instead of PGlite:**
1. PGlite runs single-connection (`--max-connections=1`); every PUT/DELETE/HEAD/LIST would contend with panel, auth and task traffic, and the WASM Postgres executes ~10–50× slower per query than native **[?, benchmark]**.
2. Object counts in the millions (restic repos create 100k+ pack files; Dokploy backups are small).
3. SQLite WAL gives many concurrent readers + one writer per bucket, ~20–50k simple inserts/s with batching, sub-ms point lookups, in-process (no IPC).
4. Bucket deletion = drop a file; backup = `sqlite3.backup()` online API (already used by `backup.py` pattern).
- Trade-off: two databases → the control-plane DB holds bucket config; the engine owns object data. Bucket stats (size/count) are pushed to PGlite once per minute for the panel/dashboard. With external PostgreSQL (multi-replica future), a `PostgresIndex` implementation of the same `ObjectIndex` interface can be selected (P2). Mark for ADR.

**Write path (PutObject, managed):**
1. Auth + policy + quota precheck (declared length) + disk watermark check (block writes at 90% of `/data`, configurable, same watermarks as docs/26 §4.5).
2. Open `tmp/<bucket>/<uuid>.part` with `O_CREAT|O_EXCL|O_WRONLY`, mode 0600.
3. Stream: decode aws-chunked if needed → update md5 + requested checksum(s) + sha256 if signed → coalesce to 1–4 MiB → `os.write` in a worker thread. Progressive size cap.
4. Verify Content-MD5 / x-amz-checksum / payload sha256 / chunk sigs / trailer. On failure: unlink temp, error.
5. `fsync(file)` per policy (§3.4), `os.rename(tmp, objects/ab/cd/<uuid>)` (same FS; both under `/data/modules/s3`).
6. Index transaction: upsert row (replacing the old row → the old content file is queued in `trash` table, not unlinked inline, so concurrent GETs that already opened the old file keep reading it — on POSIX an open fd survives unlink anyway; the queue is for crash safety).
7. Respond 200 with ETag, checksum headers, `x-amz-version-id` if versioned.

**Read path:** index lookup (in-memory LRU of hot rows, invalidated on write) → open file → stream with `os.pread` in thread (1 MiB chunks) or gateway offload (§3.6). Multipart logical layout streams across part files.

**Concurrency:** S3 semantics are last-writer-wins on PUT; no locking needed beyond the index transaction. Per-key in-process asyncio lock only for conditional writes (`If-None-Match:*`, `If-Match`) and versioning ID ordering. DeleteObjects batches in one transaction.

### 3.2 Linked-folder buckets

**Goal:** bucket `files` ↔ host directory `/srv/files`; `aws s3 ls s3://files/photos/` lists the real directory; files dropped by `scp` appear.

**Getting the host folder into the container (evaluation):**

| Option | How | Pros | Cons |
|---|---|---|---|
| **A. User-added bind mount (recommended)** | User adds `- /srv/files:/mnt/links/files[:ro]` to the MRK service in compose; panel discovers mounts under `MRK_S3_LINK_ROOTS` (default `/mnt/links`) by reading `/proc/self/mountinfo`, shows them as "available folders", user picks one + mode. Panel's "Link a folder" wizard *generates* the exact compose snippet and `docker compose up -d` instructions when nothing is mounted yet. | Zero new privileges; kernel enforces ro; full-speed I/O; works with sendfile offload; clear in compose (auditable); no data through another process | Requires a container recreate (≈ seconds of downtime for all modules) per new folder; user must edit compose. Mitigation: recommend mounting one parent (`/srv/mrk-share:/mnt/links`) once, then create subfolders freely — each subfolder can be its own bucket without further restarts. |
| B. Serve via Host Agent | Agent (already has host mounts for volume backup per doc 28 S6) exposes signed file API; s3-engine proxies reads/writes | No compose edit per folder; could reach Docker volumes | Every byte crosses another hop (HMAC JSON API not designed for bulk), agent needs broad host FS rw (expands its blast radius — doc 28 keeps it minimal), harder to stream/Range/offload, two processes must agree on atomicity |
| C. Docker volumes via Agent-created mounts | Agent recreates MRK container with new mounts | automatic | MRK would modify its own container → effectively root; rejected |

**Recommendation: A for MVP**, with a documented "one parent mount" pattern; B as P2 *read-only* option for exposing Dokploy-managed Docker volumes (e.g. let a user browse `/var/lib/docker/volumes/x/_data` read-only) because the agent already mounts volumes read-only for backup. Never mount `/` or `/var/lib/docker` read-write.

**Permissions:** MRK runs as UID 10001. Read-only links need files readable by 10001 (or world-readable); rw links need ownership or ACL (`setfacl -R -m u:10001:rwX /srv/files` + default ACL). The wizard checks access (`os.access` + test write of `.mrk-probe` in rw mode) and shows the exact `chown`/`setfacl` command. New files are created with mode from link option `file_mode` (default 0644) / `dir_mode` (0755) — umask set per write.

**Key ↔ path mapping (rules):**
- key is split on `/`; each segment maps to a path component; path = `root / seg1 / … / segN`.
- **Rejected keys** in linked buckets (`InvalidArgument`/`KeyTooLongError` with explanatory message; these are legal in S3 but not representable): empty segment (`a//b`, leading `/`), segment `.` or `..`, segment containing `\x00`, segment > 255 bytes (NAME_MAX), total path > 4096 (PATH_MAX), keys starting with reserved `.mrk/` prefix.
- **Trailing `/` keys** ("folder markers", size must be 0): mapped to a directory; PUT creates the directory (mkdir -p), GET returns 0 bytes with ETag of empty MD5 `"d41d8cd98f00b204e9800998ecf8427e"`; HEAD of `dir/` exists iff the directory exists. Listing emits directories as CommonPrefixes when a delimiter is used; **without** a delimiter, empty directories are emitted as `dir/` zero-byte keys only if `emit_dir_markers` option is on (default: emit only empty directories, so `aws s3 sync` round-trips folder structure; non-empty dirs are implied by their children).
- **File/dir conflict:** key `a/b` exists as a file and client PUTs `a/b/c` → S3 allows both; filesystem can't → `InvalidArgument` "path conflict: a/b is a file" (documented deviation). Likewise PUT `a/b` when `a/b/` is a non-empty directory.
- **Case-insensitive / normalization filesystems:** detect at link time (create `.mrk-probe-A`, stat `.mrk-probe-a`); if case-insensitive (e.g. a CIFS/exFAT mount) warn and set `case_insensitive=true` → keys differing only by case are refused on PUT to avoid silent overwrite. Unicode: keys are stored as given (bytes); no NFC/NFD normalization; if filesystem returns names that aren't valid UTF-8, they are exposed with `encoding-type=url`-safe percent-escaping `%XX` mapping and marked read-only (P1).
- Hidden/system files: option `hide_patterns` (default `.mrk/**`, `.mrk-tmp-*`, `lost+found`); option `show_dotfiles` (default on).

**Safety (no escaping the root):**
- Resolve with `openat2(RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS [| RESOLVE_NO_SYMLINKS])` via `os.open(..., dir_fd=root_fd)` per component when `openat2` unavailable in Python — Python 3.13 has no `openat2` wrapper; implement component-wise walk with `os.open(seg, O_PATH|O_NOFOLLOW|O_DIRECTORY, dir_fd=parent_fd)` for directories and `O_NOFOLLOW` on the final file (symlinks policy `deny`), or `ctypes`/`os.syscall`-less fallback: post-open check `os.path.realpath(f"/proc/self/fd/{fd}")` starts with root realpath (TOCTOU-safe because we check the opened fd, not the path).
- Symlink policy per link: `deny` (default; symlinks are invisible in listings and 403 on access), `follow-inside` (follow only if the resolved target stays under root, checked on the fd), `follow-any` (owner-only, red warning; not recommended).
- Hardlinks and device files: special files (fifo, socket, device) are never listed or opened (`stat.S_ISREG` check on the fd; opening a fifo could hang → open with `O_NONBLOCK` then fstat).
- Mount-boundary: option `one_filesystem` (default on) — do not descend into nested mounts (compare `st_dev`).

**Atomic writes:** write to `<dir>/.mrk-tmp-<uuid>` (hidden from listings) in the **destination directory** (same FS → atomic `rename`), fsync file, `os.rename` (replace), optional fsync dir. Multipart parts for linked buckets are staged in `<root>/.mrk/uploads/<id>/` if rw (same FS → final concat+rename atomic), else refused (ro). Crash leftovers `.mrk-tmp-*` older than 24 h are cleaned by GC.

**Metadata for linked buckets** (Content-Type, user metadata, tags, checksums, real MD5):
- **Sidecar DB, not sidecar files**: per-bucket SQLite index in `/data/modules/s3/meta/<bucket-id>.sqlite` keyed by key, storing `(size, mtime_ns, inode, dev, etag_md5?, checksums?, content_type?, user_meta?, tags?)`. Sidecar files (`.file.json`) pollute the user's folder; xattrs (`user.mrk.*`) are an alternative (P2 option: fast, travel with the file on same FS, but not supported on all FS and lost on copy).
- **Validity rule:** a metadata row is valid only if `(size, mtime_ns, inode)` still matches `fstat`; otherwise metadata (and MD5) is considered stale → Content-Type falls back to `mimetypes.guess_type`, user metadata dropped, ETag synthetic until re-hashed.
- **ETag:** `etag_mode` = `md5-lazy` (default: synthetic until background hasher computes MD5; hasher prioritizes recently accessed and files < 1 GB; budget-limited, e.g. 50 MB/s, configurable) | `md5-eager` (hash during reconcile) | `synthetic` (never hash; fastest; rclone users should set `--s3-no-check-md5`? — rclone: use `--ignore-checksum` **[?]**). Objects written via S3 always get real MD5 at write time.
- **Listing:** **direct directory walk** (`os.scandir`, sorted per directory by UTF-8 bytes, merged lazily) rather than index — guarantees files added externally appear immediately without inotify. To get S3 ordering, a directory's children are sorted with `/`-aware comparison (a child dir `a` contributes keys `a/…` which sort as `a/` — must be merged with sibling file names like `a-b`, `a.txt`: sort entries by `name + ("/" if dir else "")` bytes). Pagination: continuation token = last key; resuming = walk path components of last key and continue. For delimiter=`/` listings (the common case: browsing one folder), cost is one `scandir` of that directory. For flat recursive listings of huge trees (restic-style), walking is O(n) per page → cache: keep an optional **listing snapshot** in the sidecar index refreshed by reconcile (option `list_source = walk|index|auto`; auto = walk for delimiter queries, index for recursive if index fresher than N seconds).
- **Reconcile (inotify-less):** periodic task per linked bucket (default every 5 min, configurable; "Rescan now" in panel) walks the tree, updates the index (adds/removes rows, marks stale metadata), recomputes size/count stats, enqueues hashing. inotify is unreliable across bind mounts for writes from the host? (inotify does see host writes on bind mounts of the same kernel, but not on NFS/CIFS and has watch limits — `fs.inotify.max_user_watches`) → optional P2 `watch=inotify` accelerator, never relied on for correctness.
- **Read-only vs read-write mode:** `ro` → all mutations return `AccessDenied` "bucket is read-only (linked folder)" regardless of policy; recommend also mounting `:ro`. `rw` → PUT/DELETE/Copy/multipart allowed; DELETE of a key removes the file and prunes empty parent directories (option `prune_empty_dirs`, default on, never removes root).
- **Consistency caveat:** files being written by an external process appear partially. Option `stable_age_seconds` (default 0; e.g. 5 → files whose mtime is within the last 5 s are hidden from listing/GET 404) for drop-folder use cases.
- Unsupported on linked buckets: versioning, object lock, SSE, logical multipart layout. Quotas are advisory (show `statvfs` free space of the mount).

### 3.3 Large objects and limits (all configurable — docs/27)

| Setting | Default | AWS |
|---|---|---|
| `max_object_size` | 5 TiB (effectively: limited by disk) | 5 TiB |
| `max_single_put_bytes` | 5 GiB | 5 GiB |
| `multipart_min_part_size` | 5 MiB | 5 MiB |
| `multipart_max_parts` | 10000 | 10000 |
| `multipart_upload_ttl_days` (abort incomplete) | 7 | none (lifecycle) |
| `max_keys_per_list` | 1000 | 1000 |
| `max_delete_objects` | 1000 | 1000 |
| `max_xml_body_bytes` | 1 MiB (Complete with 10k parts ≈ 600 KB) | — |
| `max_header_bytes` total | 16 KiB (gateway + uvicorn `h11_max_incomplete_event_size`) | 8 KB for headers? **[?]** |
| `max_user_metadata_bytes` | 2 KiB | 2 KB |
| `max_key_bytes` | 1024 | 1024 |
| `max_buckets` | 1000 | 10000 default quota |
| `clock_skew_seconds` | 900 | 900 |
| `presign_max_expiry_seconds` | 604800 | 604800 |
| `fsync_policy` | `object` | — |
| `disk_watermarks` | 80/90/95 | — |
| `idle_body_timeout_seconds` | 120 | ~20 s **[?]** |

### 3.4 fsync policy

`fsync_policy`: `none` (fast, risk losing last seconds on power loss — never produces a torn/garbage object because rename only happens after write completes, but renamed file may be empty after crash on ext4 without `auto_da_alloc`… ext4 has auto_da_alloc for rename-replace; XFS does not **[M]**), `object` (default: fsync file before rename + fsync parent dir every N ms batched), `strict` (fsync file + dir per object, before responding). Index SQLite: `journal_mode=WAL`, `synchronous=NORMAL` for `object` policy (durable at checkpoint; lose last txns on power loss but never corrupt), `FULL` for strict. Crash recovery (§3.7) reconciles index vs files either way.

### 3.5 Garbage collection & crash recovery

GC task (hourly default, in s3-engine):
1. Remove `tmp/` files older than `tmp_ttl` (6 h) not owned by an active request (in-memory registry of open temp files).
2. Abort multipart uploads older than `multipart_upload_ttl_days` (and per-bucket lifecycle `AbortIncompleteMultipartUpload`) → delete parts dirs.
3. Process `trash` queue (content files superseded/deleted) after `trash_grace` (60 s, lets in-flight GETs on other workers finish if we ever run >1 worker; also P2 "undelete within N hours" feature).
4. **Orphan sweep** (daily): files under `objects/` not referenced by index (crash between rename and index commit) older than 1 h → moved to `trash` then deleted; index rows whose file is missing → marked `corrupt`, GET returns 500 InternalError + alert (never silently 404).
5. Linked buckets: `.mrk-tmp-*` > 24 h, `.mrk/uploads/*` per TTL.

Startup recovery: open SQLite (WAL recovery automatic), run step 4 in "quick" mode for files modified in the last hour, rebuild in-memory counters from `SELECT sum(size), count(*)`.

### 3.6 Downloads: streaming and sendfile offload

Same seam as docs/26 §5.2: uvicorn copies through userspace (no ASGI zerocopysend). P1 flag `download_offload=true`: s3-engine authorizes, sets all S3 headers (ETag, Content-Type, Last-Modified, x-amz-*, Content-Disposition, CORS) and returns `X-Accel-Redirect: /_internal/s3/<bucket-id>/objects/ab/cd/<uuid>` (or Caddy `intercept`/`file_server` equivalent — depends on Gateway ADR, still open per docs/10 Gate 11). Gateway serves Range via sendfile. Not usable for logical-multipart objects (multiple files) unless compacted, or SSE objects. Linked buckets: internal location maps to `/mnt/links/...` (gateway must have the same mounts — it's the same container).

### 3.7 Upload streaming

`async for chunk in request.stream()` — no `await request.body()` anywhere except bounded XML bodies (read with a hard cap). Gateway: request buffering off, body limit per route (`s3` route: unlimited/configurable), idle timeouts ≥ 10 min, keep `Expect: 100-continue` working (uvicorn supports it; boto3 sends `Expect: 100-continue` on PUT **[M]** — gateway must pass it or answer it), preserve `Content-Encoding: aws-chunked` and `Transfer-Encoding`, preserve original `Host`, no request-header normalization (case is irrelevant to SigV4 but value whitespace and ordering of duplicate headers matter), no gzip on responses for `application/octet-stream`? (gzip breaks Content-Length/ETag expectations — disable compression on the s3 route entirely).

---

## 4. Domains & routing

### 4.1 Route kinds added to the doc-20 route registry

| route_kind | hostname example | Behavior |
|---|---|---|
| `s3-api` | `s3.example.com` | path-style API + ListBuckets |
| `s3-api-vhost` | `*.s3.example.com` (wildcard — Owner-only per doc 20 §2) | virtual-hosted API; bucket = leftmost label |
| `s3-bucket-api` | `cdn-api.example.com` → bucket X | full API, bucket implied (P1) |
| `s3-website` | `files.example.com` or `<bucket>.s3-website.example.com` | anonymous GET/HEAD only, index/error docs, redirects (P1) |

TLS terminates at the Edge Gateway (ACME or external proxy — pending cert ADR). Wildcard cert for `*.s3.<domain>` requires ACME DNS-01 → can use our DNS module (docs/25) when the zone is hosted on MRK; otherwise user supplies cert. If no wildcard: panel sets "addressing = path" and all snippets include path-style flags.

**In Dokploy co-hosting:** typically Traefik (Dokploy) owns 80/443. The MRK gateway sits behind Traefik (Traefik → MRK :8080 with Host preserved) — Traefik must route `s3.example.com` and `*.s3.example.com` to MRK, and **must not** buffer bodies (Traefik streams by default; `maxRequestBodyBytes` unset) — the wizard shows a Dokploy "domain" config / Traefik dynamic file snippet. Verify Traefik passes `Expect: 100-continue` and large chunked bodies **[?, PoC]**.

### 4.2 Custom domain per bucket

Panel: Bucket → Domains → add `files.example.com` → choose mode (website/api) → shows required DNS record (CNAME `files.example.com → s3.example.com` or A record to server IP; if the zone is in MRK DNS module, offer one-click record creation) → verification (DNS resolves to us + HTTP challenge token at `/.well-known/mrk-verify/<token>` served by gateway) → route activated → cert issuance. AWS-style "bucket name must equal the domain" is **not** required (our route table maps hostname → bucket id).

### 4.3 Static website mode (P1)

Config (from PutBucketWebsite or panel): `IndexDocument.Suffix` (e.g. `index.html`), `ErrorDocument.Key`, `RedirectAllRequestsTo{HostName, Protocol}`, `RoutingRules` (P2). Behavior on website hosts: `GET /` → `index.html`; `GET /docs/` → `docs/index.html`; `GET /docs` (no slash) when `docs/index.html` exists → 302 to `/docs/` (AWS behavior **[M]**); missing → ErrorDocument with 404 status or plain HTML 404; only objects readable by anonymous are served (bucket must be public-read or website route has implicit read grant — decision: website route **implies** anonymous GetObject for that bucket, shown explicitly when enabling; PublicAccessBlock must allow). SPA option (P1, non-AWS): `spa_fallback=true` → serve index for any 404 (useful for React apps — common for Dokploy users). Cache headers from object `Cache-Control`; gateway may add `ETag`/`Last-Modified` conditional handling (we already implement 304).

### 4.4 Presigned URL endpoint consistency

`public_endpoint` per module (e.g. `https://s3.example.com`) and `addressing_style` (path|virtual) are settings; presigning in the panel and in the connection snippets uses them. Behind Traefik/gateway the Host the client signs == public hostname → signature checks out as long as Host is preserved. Internal callers (MRK backup module, §7) use `http://127.0.0.1:9100` with Host header `s3.internal` and their own internal endpoint config — signatures computed against that host, no gateway hop.

---

## 5. Admin panel (React + MUI, i18n fa/en, Simple/Advanced per doc 28 §5)

**Simple mode**
- **Buckets list:** name, type badge (Managed / Linked ro/rw), visibility (Private / Public / Website), size, objects, last modified, quota bar. Server-side paged; stats from per-minute rollup.
- **Create bucket wizard:** (1) name (live validation), (2) type: Managed | Link a server folder (lists discovered mounts under `/mnt/links`, shows permission check result and compose snippet if empty), (3) access: Private / Public read / Website, (4) options: versioning (managed only), quota, "create access key for this bucket" checkbox → generates a `ReadWrite(bucket)` service identity and shows key once with copy buttons and ready snippets (Dokploy form values!).
- **File browser:** breadcrumb folders (delimiter `/` listing), infinite scroll pages, search by prefix, multi-select; upload via drag&drop / button — files > 16 MiB use **multipart from the browser** (parallel 4 parts, 8–16 MiB each, resumable within session, progress, cancel = Abort); upload goes **through the control plane** same-origin `/api/v1/s3/buckets/{b}/objects/...` streaming proxy to s3-engine (no CORS, uses panel session + CSRF; control plane streams without buffering) — alternative P1: browser uploads directly to `s3.<domain>` with presigned part URLs (faster, needs bucket CORS auto-config for panel origin). New folder (zero-byte `name/`), download (presigned GET redirect, so bytes don't go through control plane), delete (with confirm; folder delete = batch delete prefix with count preview and typed confirmation above N objects), rename/move (CopyObject + DeleteObject per key; folder rename = background task with progress; linked rw buckets use `os.rename` fast path — atomic, instant), **Share link** (expiry select → presigned URL + QR, list/revoke shares), **Preview** (images, PDF, video/audio via presigned Range GET, text/JSON/YAML/log ≤ 1 MB with syntax highlight; never render HTML/SVG inline in panel origin — sandboxed iframe from a different origin or download only, XSS protection), object details (metadata, tags, ETag, checksums, versions P1).
- **Access keys page:** identities list, create (template picker: Read-only bucket / Read-write bucket / Backup client / Admin; optional prefix), secret shown once, disable/rotate/delete, last used (time, IP, client UA).
- **Connection info:** endpoint, region, path-style flag, and copy-ready snippets with the selected key filled (secret only at creation time): aws cli (`aws configure` + `--endpoint-url`, `AWS_REQUEST_CHECKSUM_CALCULATION` not needed if we support it), boto3, rclone (`type = s3`, `provider = Other`, `endpoint`, `force_path_style = true`, `acl = private`), mc (`mc alias set`), s3cmd (`.s3cfg` host_base/host_bucket), restic (`s3:https://s3.example.com/bucket/restic`), Cyberduck (generic S3 profile / `.cyberduckprofile` download), WinSCP (Amazon S3 protocol, host, path-style), **Dokploy** (Destinations → S3: Access Key, Secret, Region `us-east-1`, Endpoint `https://s3.example.com`, Bucket, Provider: leave empty/Other), Laravel/Node `AWS_ENDPOINT` env snippet.
- **Usage dashboard:** total used vs disk, per-bucket top-N, requests/s, bandwidth in/out, errors, 30-day growth (reuse monitoring charts).

**Advanced mode**
- Bucket policy JSON editor (Monaco-like, schema validation, templates, simulator), CORS editor (form + XML), lifecycle editor (rules table: prefix/tag filter, expire after N days, abort MPU after N days, noncurrent versions; dry-run preview), website config, custom domains, PublicAccessBlock toggles, object lock (P2), SSE (P2), tags.
- Groups and custom IAM policies, service accounts, per-identity quotas.
- Multipart uploads in progress (list/abort), GC runs and results, reconcile status for linked buckets (last scan, files, hashing queue), integrity check (fsck sample).
- Audit view filtered to `s3.*` events: bucket/identity/policy/link/public changes (always), object writes/deletes (configurable: off / sampled / all — "all" may be large; stored in a rotating file, not PGlite, as docs/23 recommends for query logs).
- Settings page (all §3.3 limits, region, endpoints, addressing, fsync, GC intervals, rate limits) — docs/27 DoD.

Control-plane API: `/api/v1/s3/...` (buckets, objects proxy, identities, keys, policies, shares, routes, settings, stats) with CSRF and the permissions in §2.5; all destructive actions with typed confirmation + audit.

---

## 6. Compatibility & testing

### 6.1 Client matrix (CI, isolated network, existing "isolated hostnames" CI pattern)

| Client | Key behaviors to cover |
|---|---|
| **Dokploy backup destination** (pinned version) | "Test connection" (rclone ls/lsd? **[?]** — check what test does: PR shows `--s3-no-check-bucket` + `--s3-force-path-style` **[V]**), postgres/mysql/mongo backup via `rclone rcat` (unknown size → multipart), retention `keepLatestNBackups` (list + delete **[?, read source]**), restore (rclone cat/copyto → GET), volume backups. **Gate exit criterion.** |
| aws cli v2 (latest) | `s3 cp/sync/mv/rm --recursive`, `s3api` ops, multipart > 8 MB default threshold, CRC64NVME trailer default, presign, `--endpoint-url`, virtual + path style |
| boto3 (latest + one ≤ 1.35 for pre-checksum behavior) | put/get/copy/multipart via TransferManager, `generate_presigned_url/post`, checksums CRC32/CRC32C/SHA256, `when_required` mode |
| rclone (latest) | provider=Other, `copy/sync/check/lsf/cat/rcat/delete/purge/mkdir`, server-side copy (>5 GiB → UploadPartCopy), `--s3-list-version 1/2`, md5chksum metadata, `--s3-upload-cutoff`, `--checksum` |
| restic | init/backup/check/prune/restore (many small objects, ListObjectsV2 recursive, DeleteObject, HEAD, Range GET) |
| mc (MinIO client — client only, AGPL, used **only in CI**, not shipped) | `mc cp/mirror/ls/rm/share/admin`-less ops; streaming signed chunks over HTTP |
| s3cmd | v4 signing, `put/get/ls/sync/setacl/ws-create` (website), multipart |
| Cyberduck / WinSCP | manual test checklist per release (GUI); Cyberduck probes for `?versioning`, `?acl`, `?location`, accelerate **[?]** |
| Browser | POST policy form, presigned PUT from JS, CORS preflight |
| Laravel Flysystem / aws-sdk-js v3 / Go SDK v2 | smoke (common app stacks on Dokploy) |

### 6.2 Conformance suites

- **ceph/s3-tests** (MIT license; pytest + boto3): run the `s3tests_boto3/functional/test_s3.py` subset with `-m 'not fails_on_rgw…'` style markers; we maintain an **expected-failures list** (`mrk-s3tests-exclude.txt`) for unsupported features (SSE-KMS, replication, logging, IAM STS, SigV2). Track pass rate per release; MVP target ≥ 70% of non-excluded tests in categories bucket/object/multipart/list/auth/presign/copy/conditional; P1 ≥ 85% incl. versioning/lifecycle/cors/policy.
- **minio/mint** (Apache-2.0 container running aws-cli, awscli, mc, minio-go, s3cmd, aws-sdk-go/java/php/ruby, s3select tests): run in CI as a black-box container against our endpoint (`SERVER_ENDPOINT`, `ACCESS_KEY`, `SECRET_KEY`, `ENABLE_HTTPS`, `MINT_MODE=core`); disable s3select and minio-specific admin suites. Mint is a client harness only — no MinIO server code involved, so docs/23 clean-room holds.
- **Our pytest suite:** SigV4 canonicalization golden vectors (AWS SigV4 test suite `aws-sig-v4-test-suite` + S3-specific examples from AWS docs: "GET object", "PUT object with chunked signing" example with known signatures), fuzz (Hypothesis) of keys/path mapping, aws-chunked decoder (boundary splits at every byte offset), XML parser hostile inputs, policy evaluator truth tables, listing ordering vs a reference model (random keys, random delimiters, compare with an in-memory sort model), linked-folder traversal attempts (symlink races with a concurrent attacker thread swapping dirs↔symlinks).
- **Chaos:** kill -9 s3-engine during PUT / Complete / DeleteObjects / GC → restart → invariants (no index row without file except marked corrupt, no visible partial object, orphan sweep cleans); disk full during PUT (ENOSPC → 507? AWS uses 500/503; we return 503 `SlowDown` or `InsufficientStorage`? **decide**: 507 is not S3; use 500 InternalError with message, plus watermark block earlier); client disconnect mid-upload; slowloris body; PGlite down (S3 data plane must keep serving with cached identities — auth cache TTL; writes continue since index is SQLite; only config changes fail); clock skew; network partition between Traefik and gateway.
- **Load:** locust/k6 + `warp`? (minio/warp is AGPL → CI-only tool, fine) or `s3-benchmark`; scenarios: 1×10 GB PUT/GET, 64 parallel 64 MB, 10k × 4 KB PUT (small-object rate), LIST of 1M-key bucket (paging p99), restic backup of 50k files.

---

## 7. Integration with Gate 18 backups (docs/28 S6)

- **MRK backup module → our S3 as destination:** the backup worker already plans a native SigV4 S3 client (doc 28 S6 "امضای SigV4 بومی"). Share code: one `sigv4.py` module (signer + verifier, golden tests used both ways) in `mrk_control_plane/s3common/`. Destination type `mrk-local-s3` = loopback `http://127.0.0.1:9100`, bucket picked from list, internal service identity `svc-backup` auto-created with `BackupClient(bucket, prefix)` policy; no gateway/TLS hop, no egress. Writes use multipart (MRKBKP2 stream of unknown length; 16–64 MiB parts) with CRC32C/SHA256 checksum per part. **Caveat (show in UI):** backing up to S3 on the same disk protects against app-level mistakes, not disk/server loss — recommend replication to an external S3 (below) or object lock (P2) for ransomware protection.
- **Self-backup ordering:** MRK's own appliance backup must exclude `/data/modules/s3/buckets` by default (can be huge) but include `meta/*.sqlite` via SQLite online backup and the identity/policy tables + SecretStore envelope (encrypted keys; restore needs the key file — same rule as upstream secrets). Option "include bucket contents" with size warning.
- **External S3 (ArvanCloud, Liara, AWS, Cloudflare R2, Wasabi):** same client, endpoint + region + path-style toggle per destination, traffic via `outbound.py` `OutboundClient` (proxy profiles, `vetted_addresses` SSRF checks, `netresolve` custom DNS) — external destinations are normal outbound destinations; `allow_private=false` except the explicit local-S3 type. Arvan endpoints like `s3.ir-thr-at1.arvanstorage.ir` **[?, verify current]**, Liara `storage.iran.liara.space` **[?]** — offer as presets, editable.
- **P1 replication feature** (non-AWS-API, panel-driven): "mirror bucket X to external destination Y" scheduled job (rclone-like sync implemented natively: list both sides, compare size+ETag/md5 metadata, copy missing/changed via multipart, optional delete) — gives the solo DevOps user off-site copies of Dokploy backups landing in our S3.
- Dokploy itself can target our S3 directly (it then manages its own retention); MRK backup module can alternatively trigger Dokploy backups via API (doc 28 S1) — both paths documented.

---

## 8. Performance (honest assessment)

**Per-byte CPU costs in CPython 3.13 (single core, x86-64 with SHA-NI; estimates — benchmark in PoC):**

| Operation | Throughput/core | Notes |
|---|---|---|
| MD5 (`hashlib`, OpenSSL) | ~600–800 MB/s | No HW accel; mandatory for ETag of every PUT/part |
| SHA-256 | ~1.5–2 GB/s (SHA-NI) | only for signed payloads/chunks or SHA256 checksum |
| CRC32 (`zlib.crc32`) | ~1–3 GB/s (zlib-ng in 3.13? depends on build) **[?]** | boto3 default |
| CRC32C / CRC64NVME (`awscrt.checksums`) | multi-GB/s (HW) | CLI v2 default is CRC64NVME — **pure-Python fallback would be ~10 MB/s: unacceptable**, so `awscrt` (Apache-2.0, wheel ~ few MB **[?]**) is a hard dependency; alternative `crc32c` PyPI is LGPL — avoid |
| Event loop + memcpy (uvicorn/httptools, 64 KiB recv) | ~0.5–1.5 GB/s | coalescing to 1 MiB writes helps |
| TLS | at gateway, not Python | |

`hashlib` releases the GIL for buffers > 2 KiB, so MD5 + CRC can run in a thread pool in parallel with the event loop; per *stream* the MD5 is the cap (~600 MB/s), across streams it scales with cores (1 worker process still benefits because hashing happens in threads). **Expected:** single-stream PUT ~250–500 MB/s (unsigned payload) / ~200–400 MB/s (signed chunks: MD5 + SHA-256); GET ~500 MB/s–1 GB/s in Python, disk/NIC-bound with sendfile offload. Small objects: ~800–2000 PUT/s (fsync-bound on `object` policy; SQLite batched commit with group-commit window 2–5 ms) and ~3–5k HEAD/GET-small/s.

For the target user (1 Gbps NIC ≈ 120 MB/s; Iranian international bandwidth far lower; Dokploy backups of a few GB nightly), Python is **sufficient with margin**.

**PGlite pressure:** with the per-bucket SQLite index the S3 data plane touches PGlite only for (a) identity/key/policy cache refresh (generation poll every 2 s → 1 cheap query), (b) per-minute stats flush, (c) audit of management ops. Object audits go to a rotating JSONL file. Auth lookups are served from an in-memory snapshot. Result: zero PGlite queries per S3 request in steady state. If PGlite is down, S3 continues serving with the last snapshot (fail-static), with management APIs failing.

**When a native data plane would be justified:** sustained >1 GB/s PUT per stream, >500 concurrent connections, or very high small-object rates (>10k req/s). Then: own minimal Go/Rust data plane for GET/PUT bytes only (auth decision + index stay in Python via local RPC), ~3–5k LOC — not for MVP; revisit after benchmark. The gateway sendfile offload (P1) closes most of the GET gap without a new language.

**Process model:** 1 uvicorn worker for MVP (SQLite writer is per-process; multiple workers need a single writer → either SQLite with busy-timeout across processes (works with WAL, writers serialize), or a writer actor). Measure before scaling.

---

## 9. Security

| Threat | Control |
|---|---|
| **SigV4 canonicalization bypass** | Use raw path bytes; encode each segment exactly once per S3 rules (S3 does *not* double-encode, unlike other services); don't collapse `//`, `.`, `..` — the **canonical URI must be derived from the same raw path we route on** (route-vs-sign mismatch is the classic bypass: sign `/a/b`, route `/a/../b`). Reject requests where decoded path contains `..` segments for path-style bucket detection ambiguity? — S3 keys may legally contain `..`; managed buckets don't map keys to paths, so allow; linked buckets reject (§3.2). Query canonicalization: sort by encoded key bytes, duplicated params preserved in order of value, `+` in query treated as literal `+`?? (AWS: `%20` for space; `+` in raw query is a literal `+` that must be encoded as `%2B` in the canonical form) — golden tests. |
| Header case / whitespace / duplicates | Lowercase names; trim + collapse sequential spaces; duplicates joined with `,` in received order (ASGI preserves order). Gateway must not merge/reorder duplicates. |
| Unsigned x-amz-* headers | Reject any `x-amz-*` present but not signed (except in presigned query mode where they must be in the query or signed headers) — prevents injecting `x-amz-copy-source`, `x-amz-acl`, `x-amz-metadata-directive` into a presigned PUT. |
| Empty payload hash confusion | `x-amz-content-sha256` value is part of the signature; if it claims a hex hash, enforce it; if `UNSIGNED-PAYLOAD` but the key is configured `require_signed_payload` → reject. Never treat a missing header as unsigned in header auth (compat flag only). |
| aws-chunked tricks | Verify each chunk signature *before* the next chunk counts; strict hex parse (no `+`, no leading spaces, size ≤ cap), decoded length must equal header; extensions other than `chunk-signature` rejected; trailer names must be declared. |
| Presigned scope | Presigned URL binds method, path, signed headers & query; `X-Amz-Expires` ≤ 7 d and ≤ key's `max_presign_seconds` policy; content-type/length not bound unless signed → panel presigned PUTs sign `content-type` and `x-amz-checksum-*`? (P1) ; revoke via key disable or share table. Presigned requests cannot use `response-*` overrides unless signed (they are in the query, so signed). |
| Path traversal via keys | Managed: keys never become paths (UUID storage). Linked: component-wise `O_NOFOLLOW` walk with `dir_fd`, `/proc/self/fd` realpath verification, `..`/`.`/empty/NUL rejection, `st_dev` boundary, special-file refusal, symlink policy. Hidden `.mrk/` reserved. |
| XML parsing (XXE, billion laughs) | `defusedxml.ElementTree` (forbid DTD, entities, external refs) or hand-rolled streaming parser on `xml.parsers.expat` with `SetParamEntityParsing(NEVER)` + DOCTYPE rejection; body cap per op (DeleteObjects 1000 keys ≈ 1.1 MB worst case → cap 2 MiB; Complete 10k parts → 1 MiB; policy/CORS/lifecycle 64 KB); depth cap 32; element-count cap. Responses built with escaping (`xml.sax.saxutils.escape` + reject XML-invalid chars). |
| DoS | Gateway per-IP and per-key rate limits (configurable); max concurrent uploads per key (e.g. 64) and global; max multipart uploads in progress per bucket (e.g. 10k); header size cap 16 KiB; request-line cap; idle body timeout; slow-read protection on downloads (send timeout); LIST cost limits (max-keys ≤ 1000; linked-folder walk time budget per page 2 s → return truncated page early with a continuation token — S3 allows fewer keys than max with IsTruncated=true); DeleteObjects ≤ 1000; auth failure throttling per AKID+IP (reuse `AuthStore` lockout pattern) — avoid unbounded secret decrypt per bad request (cache negative AKID lookups). |
| Public bucket risks | Global "Allow public buckets" off by default; PublicAccessBlock per bucket; panel shows red "Public" badge, typed confirmation, audit + notification (S5) when a bucket becomes public; public LIST (`s3:ListBucket` to `*`) requires an extra explicit checkbox ("anyone can list all files"); website mode serves only GET/HEAD; never public writes unless Owner explicitly crafts a policy (warning). |
| Website/custom domains: XSS on shared origins | Website buckets on **their own hostname** (never under the panel's domain or sharing cookies). The panel never serves user content from its origin (preview via presigned URL on `s3.<domain>` with `Content-Disposition: attachment` for HTML/SVG, or sandboxed iframe). Set `X-Content-Type-Options: nosniff` on all object responses. Panel cookies scoped to `panel.<domain>` host-only — not `.domain` — so `*.s3.domain` content can't read/set them. |
| CORS misconfig | Never `Access-Control-Allow-Credentials: true` (S3 doesn't use cookies); wildcard origin allowed but highlighted; the S3 API host does not trust panel sessions at all (no cookie auth on s3 routes). |
| SSRF | s3-engine makes no outbound requests except P1 replication/external backup via `outbound.py` with vetted destinations; CopyObject source is always local. |
| Secret exposure | Secrets in SecretStore (AES-GCM), shown once; redaction of `Authorization`, `X-Amz-Signature`, `X-Amz-Credential` (keep AKID), `x-amz-security-token` in logs and access logs; presigned URLs in audit stored without signature. `SignatureDoesNotMatch` debug details only when enabled per key. |
| Linked folder abuse by panel users | `s3:link:write` owner-only; links only to mounts under `MRK_S3_LINK_ROOTS`; never `/data` itself (would expose secrets, DB) — explicit denylist: `/data`, `/proc`, `/sys`, `/etc`, `/`, the docker socket path, any mount whose source is `/` or `/var/lib/docker` (from mountinfo) unless `ro` and owner confirms. |
| Multi-tenant isolation | Upload IDs bound to bucket/key/initiator? (AWS lets any authorized principal complete an upload — keep AWS semantics but require `s3:PutObject` on the key); continuation tokens HMAC-signed; bucket IDs (not names) in internal paths. |
| Time-of-check races | Policy evaluated at request start; key disabled mid-upload → upload completes (AWS-like); presign expiry checked at start only (AWS-like). |

---

## 10. Module architecture, phasing & effort

### 10.1 Architecture recommendation

**Separate process `s3-engine`** (supervisord program, uvicorn on `127.0.0.1:9100`, `--loop uvloop --http httptools`, 1 worker), published only via the Edge Gateway — *not* inside the control-plane process. Reasons: failure isolation (doc 20 §5: a 50 GB upload or a hashing backlog must not starve the panel/API), separate resource limits (doc 23 §4 budget: target 80 / 300 MB RAM, 0.5 CPU idle-peak), its own restart/crash-loop handling, and the event loop is dedicated to byte streaming. Code lives in `mrk_control_plane/modules/s3/` (shared package, second entry point `mrk-s3-engine` like `mrk-pypi-router`/`mrk-agent`), sharing `secret_store`, `outbound`, `tasks`, logging, metrics. The control plane hosts management APIs `/api/v1/s3/*` and talks to the engine over loopback with a service HMAC (reuse `agent/signing.py` pattern) for object-proxy and admin operations (rescan, GC, stats).

```text
Client (aws/rclone/Dokploy) ─TLS─> Traefik(Dokploy)? ─> Edge Gateway :8080 ─(Host preserved, no buffering)─> s3-engine 127.0.0.1:9100
                                                                     │ X-Accel offload (P1) ─> /data/modules/s3, /mnt/links
Panel ─> control-plane /api/v1/s3/* ── HMAC loopback ──> s3-engine (admin/object proxy)
s3-engine: [router+SigV4] → [policy eval (in-mem snapshot)] → [bucket backend: Managed | Linked] → [ObjectIndex: SQLite per bucket]
           [tasks: GC, lifecycle, reconcile, hasher, stats flush → PGlite]
Module manifest (doc 20 §4): id=object-s3, process=s3-engine, routes=[s3-api, s3-api-vhost, s3-bucket-api, s3-website],
  dataRoot=/data/modules/s3, health=/internal/health/{live,ready}, backup=true, migrations=true
```

Readiness: ready when SQLite indexes open, identity snapshot loaded, data dir writable, disk below the block watermark (degraded otherwise, still serving reads).

Metrics (Prometheus): `mrk_s3_requests_total{op,code}`, `mrk_s3_request_seconds{op}`, `mrk_s3_bytes_{in,out}_total{bucket}`, `mrk_s3_objects{bucket}`, `mrk_s3_bucket_bytes{bucket}`, `mrk_s3_multipart_inflight`, `mrk_s3_auth_failures_total{reason}`, `mrk_s3_gc_reclaimed_bytes_total`, `mrk_s3_linked_reconcile_seconds`, `mrk_s3_hash_queue`.

### 10.2 Phasing

Assumptions: one experienced Python engineer, includes tests/docs, excludes the shared Gateway ADR (Gate 11) which is a **hard dependency** (Host preservation, no buffering, wildcard routes, offload).

**MVP — Gate S3-1 (≈ 9–11 engineer-weeks)**
1. Module skeleton, manifest, supervisord program, health, metrics, migrations (`s3_*`), settings page plumbing. (0.5 w)
2. Router (raw path, path-style + vhost), XML writer/parser (safe), error model, request IDs. (1 w)
3. SigV4 header + presigned verifier, aws-chunked decoder (signed/unsigned/trailer), checksums (MD5/CRC32/CRC32C/CRC64NVME/SHA1/SHA256) with golden tests. (2 w)
4. Identities, access keys (SecretStore), built-in policy templates + evaluator (Allow/Deny, wildcards, basic conditions: SourceIp, SecureTransport, s3:prefix), panel RBAC permissions. (1.5 w)
5. Managed storage: SQLite index, PUT/GET/HEAD/DELETE/DeleteObjects/Copy, Range, conditionals, metadata, ListObjects V1/V2 with delimiter/encoding, ListBuckets/Create/Delete/Head/Location. (2 w)
6. Multipart (all 7 ops, logical layout, ETag-N, composite checksums), GC + crash recovery, quotas, watermarks. (1.5 w)
7. Linked folders (read-only + read-write), mount discovery, path mapping, safe walker, listing by walk, sidecar index, reconcile, lazy MD5. (1.5 w)
8. Panel MVP: buckets list/wizard, file browser (upload via CP proxy incl. multipart, download, delete, folders, share links), access keys, connection snippets incl. Dokploy. (1.5–2 w)
9. CI: Dokploy backup+restore e2e, aws cli v2, boto3, rclone, restic, s3cmd smoke; s3-tests subset; chaos kill tests. (1 w overlapping)

Exit criteria: Dokploy Postgres backup → our S3 → restore works with retention; `aws s3 cp` 10 GB with CLI v2 defaults (CRC64NVME trailer) passes; restic init/backup/check/prune green; s3-tests core subset ≥ 70%; linked folder shows externally added file within one LIST; traversal/symlink tests green; kill -9 chaos invariants hold; RSS < 300 MB during 10 parallel 1 GB uploads; no engine port exposed.

**P1 — Gate S3-2 (≈ 7–9 engineer-weeks)**
Versioning + ListObjectVersions; lifecycle (expiration, abort MPU, noncurrent) with dry-run; bucket CORS + OPTIONS; bucket policy (full subset + Principal + simulator) and canned ACLs public-read with PublicAccessBlock; static website hosting + custom domains (route kinds, DNS verification, SPA fallback); POST policy uploads; object tagging + GetObjectAttributes; FULL_OBJECT CRC combine; If-Match / If-None-Match conditional writes; gateway sendfile offload; browser direct presigned multipart; replication-to-external job + Gate 18 backup destination integration; groups, service-account subset policies, per-identity quotas; audit file + usage dashboard; mint core + s3-tests ≥ 85%.

**P2 — Gate S3-3 (≈ 8–10 engineer-weeks)**
Object lock (governance/compliance, legal hold); SSE-S3 (chunked AEAD, Range-capable) and possibly SSE-C; tag-based policy conditions; linked-folder xattr metadata, inotify accelerator, Host-Agent read-only volume browsing; Postgres-backed index option for HA; content dedup; event notifications via webhook/S5 (non-AWS format, or a subset of S3 event JSON); bucket inventory/CSV export; optional SigV2 compat flag; native data-plane only if benchmarks demand.

### 10.3 Main risks

1. **Gateway ADR (Gate 11) not decided** — S3 needs Host preservation, `Expect: 100-continue`, no buffering, wildcard host routes, large bodies; and in Dokploy setups Traefik in front. Put these into the Gateway ADR now. Without wildcard DNS/TLS, virtual-hosted style is unavailable (path-style still works for every listed client).
2. **SDK churn** (2025 default checksums broke many S3 clones; future defaults may change again) → keep latest-SDK tests in nightly CI; feature flags to relax.
3. **Signature edge cases** behind proxies → golden-vector tests + a "signature debug" mode per key.
4. **Linked-folder semantics** (ETag expectations of rclone, file/dir conflicts, permissions as UID 10001) → clear documented deviations, wizard checks.
5. **Disk-full on a shared PaaS server** (S3 uploads filling the disk Dokploy apps need) → watermarks on the host filesystem via `statvfs` (not just quota), notifications, recommendation of a separate volume/partition for `/data/modules/s3`.
6. **Scope creep toward full AWS parity** — hold to the phase lists; `NotImplemented` is a valid answer.

---

## Appendix A — Connection snippets (wizard output examples)

```bash
# aws cli v2
aws configure set aws_access_key_id MRKXXXXXXXXXXXXXXXXX
aws configure set aws_secret_access_key '<secret>'
aws configure set region us-east-1
aws --endpoint-url https://s3.example.com s3 ls s3://backups/
# (path-style if no wildcard DNS) ~/.aws/config: [default] s3 = addressing_style = path
```
```ini
# rclone.conf
[mrk]
type = s3
provider = Other
access_key_id = MRK…
secret_access_key = …
endpoint = https://s3.example.com
region = us-east-1
force_path_style = true
acl = private
```
```bash
mc alias set mrk https://s3.example.com MRK… '<secret>' --api S3v4 --path on
restic -r s3:https://s3.example.com/backups/restic init
```
```python
import boto3
from botocore.config import Config
s3 = boto3.client("s3", endpoint_url="https://s3.example.com", region_name="us-east-1",
                  aws_access_key_id="MRK…", aws_secret_access_key="…",
                  config=Config(s3={"addressing_style": "path"}, signature_version="s3v4"))
```
```ini
# ~/.s3cfg
host_base = s3.example.com
host_bucket = s3.example.com      ; path-style (or %(bucket)s.s3.example.com with wildcard DNS)
use_https = True
signature_v2 = False
bucket_location = us-east-1
```
Dokploy → Settings → S3 Destinations → Add: Name `MRK`, Access Key `MRK…`, Secret Key `…`, Bucket `backups`, Region `us-east-1`, Endpoint `https://s3.example.com`, Provider: none/Other → Test.

## Appendix B — Sources consulted

- Dokploy backup utils (rclone flags, `rcat` streaming, `--s3-force-path-style`, `--s3-no-check-bucket`, provider, additionalFlags): https://raw.githubusercontent.com/Dokploy/dokploy/canary/packages/server/src/utils/backups/utils.ts (fetched 2026-11-08) **[V]**; docs https://docs.dokploy.com/docs/core/aws-s3 , https://docs.dokploy.com/docs/core/actions ; retention `keepLatestNBackups` not yet read **[?]**.
- AWS SDK default data-integrity protections (CRC32 default for boto3; CRC64NVME for CLI v2; `request_checksum_calculation`/`response_checksum_validation` WHEN_SUPPORTED vs WHEN_REQUIRED, `AWS_REQUEST_CHECKSUM_CALCULATION`): https://docs.aws.amazon.com/sdkref/latest/guide/feature-dataintegrity.html **[V]**; Java v2 ≥ 2.30.0: https://docs.aws.amazon.com/sdk-for-java/latest/developer-guide/s3-checksums.html
- SigV4 streaming with trailers: https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-streaming-trailers.html (page body did not render in fetch; format summarized from secondary/memory — **re-verify**), SigV4 streaming (signed chunks): https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-streaming.html , header auth https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html , query auth https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-query-string-auth.html , POST policy https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-HTTPPOSTConstructPolicy.html
- S3 API reference (operations, errors): https://docs.aws.amazon.com/AmazonS3/latest/API/API_Operations_Amazon_Simple_Storage_Service.html , https://docs.aws.amazon.com/AmazonS3/latest/API/ErrorResponses.html — memory-based in this draft **[M]**.
- Conformance: https://github.com/ceph/s3-tests (MIT), https://github.com/minio/mint (Apache-2.0; client harness only).
- Repo context: `README.md`, `docs/20`, `docs/23`, `docs/26`, `docs/27`, `docs/28`, `docs/29`; code `secret_store.py` (AES-GCM envelope, single JSON file), `outbound.py` (ProxyProfile, vetted_addresses, OutboundClient), `backup.py` (MRKBKP2), `auth.py` (ROLE_PERMISSIONS), `deploy/appliance/supervisord.conf` (PGlite `--max-connections=1`), `compose.yaml` (single `/data` mount, `mrk-agent` internal network).
