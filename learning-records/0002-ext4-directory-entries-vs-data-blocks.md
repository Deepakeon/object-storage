# Directory Entries vs. Data Blocks & Two-Layer Hashing in ext4

Resolved a fundamental distinction in filesystem architecture: ext4 directory blocks store directory entries (filenames and inode numbers) rather than file payload bytes, meaning entry capacity (56 entries per 4KB block) is completely decoupled from payload file size. Clarified the two distinct hashing layers: application-level SHA-256 (256-bit key addressing) vs kernel-level ext4 HTree (32-bit filename indexing vulnerable to Birthday collisions at ~65k entries).

## Evidence
Addressed learner questions regarding whether payload sizes exceeding 4KB alter the 56-entries-per-block limit, and clarified why ext4's 32-bit HTree hash is distinct from the Storage Engine's 256-bit SHA-256 key hash.

## Implications
Solidifies why 2-tier directory partitioning works identically for 1KB text files and 10GB video streams, and reinforces how ext4 extent trees manage variable payload allocations independently of dentry caches.
