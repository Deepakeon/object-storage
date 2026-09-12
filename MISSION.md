# Mission: Storage Engine Internals & S3-Compatible Filesystem Architecture

## Why
Master the principles of low-level POSIX and Linux ext4 filesystem internals, cryptographic content addressing, and data/metadata decoupling to build and operate robust, high-performance, S3-compatible storage engines.

## Success looks like
- Articulate the mechanical limits of Linux ext4 (HTree 32-bit hash collisions, 4KB block entry limits, `EXT4_LINK_MAX`, non-shrinking directories) and how 2-tier directory partitioning mitigates them.
- Explain why cryptographic hashing (SHA-256 lowercase hex) completely eliminates path traversal vulnerabilities (CWE-22) and POSIX file-versus-directory namespace collisions.
- Distinguish the operational roles of the disk Storage Engine (raw binary payloads) versus the embedded Metadata Store (logical keys, MIME types, timestamps, custom headers).
- Calculate and evaluate the scaling trade-offs between 1-tier and 2-tier directory fan-outs for workloads exceeding 1,000,000 objects per bucket.

## Constraints
- Ground all architectural explanations in Linux POSIX filesystem semantics, kernel behaviors, and Java NIO filesystem operations.
- Ground complex operating system mechanics in intuitive layman analogies before delving into kernel structures.

## Out of scope
- Distributed multi-node consensus algorithms (Raft/Paxos) and erasure coding (reserved for subsequent multi-node storage phases).
- S3 XML API wire protocol serialization (focusing on storage engine layout and data/metadata separation).
