# Learning Notes & Preferences

- **Learner Focus**: Wants deep, intuitive understanding grounded in engineering reality. Prefers layman explanations alongside concrete low-level kernel mechanics (e.g. ext4 structures, HTree hashing, dentry cache hits).
- **Context Anchors**: Rooted directly in [ADR 0001](file:///home/deepak/Documents/object-storage/docs/adr/0001-storage-engine-layout.md) and [Research Doc 0002](file:///home/deepak/Documents/object-storage/docs/research/0002-filesystem-storage-layout.md).
- **Core Topics Covered**:
  1. What is a POSIX filesystem? (File vs dir impedance mismatch, hierarchical inodes, syscalls)
  2. What is ext4? (Linux's default journaled filesystem, blocks, inodes, directories as entry lists)
  3. Directory scaling and ext4 limits in layman terms (The 1M items cardboard box vs 2-tier filing cabinet, 56 entries per 4KB block, HTree 32-bit hash collisions, unshrinking directories, `EXT4_LINK_MAX`)
  4. Hashed key addressing (Why lowercase hexadecimal SHA-256 digest of raw UTF-8 bytes: collision resistance, uniform spread, case-sensitivity safety, CWE-22 elimination)
  5. What are MIME types? (Why payloads on disk have no extension, how the Metadata Store preserves MIME types and supplies `Content-Type`)
