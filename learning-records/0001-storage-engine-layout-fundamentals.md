# Storage Engine Layout & Linux ext4 Fundamentals

Established foundational understanding of POSIX filesystem mechanics, ext4 directory block constraints (56 entries per 4KB block, HTree collisions at ~65k entries, non-shrinking directories), cryptographic hash decoupling with lowercase SHA-256, and the architectural separation between raw disk payloads and database-tracked MIME types/metadata in ADR 0001.

## Evidence
Explored and clarified why raw S3 keys cannot be directly mapped to disk paths, why a 2-tier fan-out is required over a flat directory for scaling beyond 1M objects, and why MIME types reside in the embedded Metadata Store rather than filesystem file extensions.

## Implications
Unlocks implementation of the Storage Engine write pipeline (atomic staging and moves, lazy directory creation) and the schema design of the Metadata Store without risking ext4 HTree performance degradation or CWE-22 path traversal.
