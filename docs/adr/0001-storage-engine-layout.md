# ADR 0001: 2-Tier SHA-256 Partitioned Filesystem Storage Engine Layout

## Status
Accepted

## Context
The **Storage Engine** must persist raw object **Payloads** on a local POSIX filesystem (Linux ext4) given an arbitrary S3 **Key** within a **Bucket**.

Directly mapping user-supplied keys to disk paths introduces severe risks:
1. **Security (CWE-22 Path Traversal)**: S3 keys can contain `../`, null bytes, absolute paths, or special characters.
2. **POSIX Namespace Conflicts**: In S3, `photos` and `photos/beach.png` can coexist as distinct objects. On a POSIX filesystem, a single path cannot simultaneously be a regular file and a directory (`EISDIR` / `ENOTDIR`).
3. **Directory Scaling & ext4 Limits**: Putting hundreds of thousands of files in a flat directory triggers ext4 HTree 32-bit hash collisions, forcing multi-block linear scans and severe performance degradation. Furthermore, directories never shrink their physical allocated blocks when files are unlinked.
4. **Crash Consistency**: Direct-to-target writes risk partial payload corruption on server crash or concurrent overwrites.

## Decision
1. **Hashed Key Addressing**:
   The Storage Engine will compute the lowercase hexadecimal SHA-256 digest of the raw UTF-8 key bytes:
   $$\text{hash} = \text{hex\_lower}(\text{SHA-256}(\text{key.getBytes(StandardCharsets.UTF\_8)}))$$
2. **2-Tier Directory Partitioning**:
   Payloads will be stored at:
   `/data/buckets/{bucket}/{hash[0:2]}/{hash[2:4]}/{hash}`
   - Tier 1: 256 directories (`00` to `ff`)
   - Tier 2: 256 subdirectories (`00` to `ff`), creating $65,536$ leaf directories per bucket.
   - At 1,000,000 objects per bucket, average files per leaf directory is $\approx 15.26$, meaning each leaf directory fits completely within a single 4KB ext4 filesystem block (zero HTree splitting, $O(1)$ dentry cache hits).
3. **Co-located Staging & Atomic Moves**:
   - Payloads stream into `/data/staging/{bucket}/{uuid}.tmp` located on the **same filesystem mount** as `/data/buckets/`.
   - On completion, `FileChannel.force(true)` is called, followed by `Files.move(staging, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)`.
   - Overwrites are atomic; concurrent readers holding open file descriptors continue reading unlinked inodes without error.
4. **Metadata Store Decoupling**:
   Human-readable keys, MIME types, creation timestamps, and custom attributes are persisted exclusively in the **Metadata Store** (embedded database), decoupling logical key indexing from raw payload disk paths.

## Consequences
- **Positive**:
  - Immunity from path traversal attacks (CWE-22) at the architectural boundary.
  - Zero POSIX file/directory collision errors.
  - Uniform $O(1)$ disk access times up to 10M+ objects per bucket.
  - Safe concurrent writes and crash consistency with no partial file reads.
- **Negative**:
  - Browsing `/data/buckets/` via standard CLI tools requires querying the Metadata Store to translate hashes back to human-readable keys.
  - Creating two levels of directories incurs two inode lookups per file access (mitigated by Linux dentry caching).
