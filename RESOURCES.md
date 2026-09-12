# Storage Engine & Linux Filesystem Resources

## Knowledge

- [Linux Kernel Documentation: ext4 Directory Indexing](https://www.kernel.org/doc/html/latest/filesystems/ext4/directory.html)
  Authoritative Linux kernel documentation on HTree indexing (`dir_index`), directory entry structures (`ext4_dir_entry_2`), and leaf block chaining. Use for: understanding directory scaling, block layouts, and HTree mechanics.
- [Git Repository Format Documentation: Loose Objects (`gitrepository-layout`)](https://git-scm.com/docs/gitrepository-layout)
  Official Git specification detailing the 1-byte (256 directory) fan-out for loose objects. Use for: historical architectural precedent of content-addressed and hashed filesystem storage.
- [RFC 6234: US Secure Hash Algorithms (SHA and SHA-based HMAC and HKDF)](https://datatracker.ietf.org/doc/html/rfc6234)
  IETF standard specification for SHA-256. Use for: collision resistance properties, digest lengths, and deterministic bit distributions.
- [RFC 2046 & RFC 6838: Media Type Specifications and Registration Procedures (MIME)](https://datatracker.ietf.org/doc/html/rfc6838)
  Standards defining MIME / Media Types. Use for: HTTP `Content-Type` handling and metadata classification.
- [MITRE CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')](https://cwe.mitre.org/data/definitions/22.html)
  Security vulnerability definition. Use for: understanding path escape attack vectors (`../`, null bytes) in file-backed services.

## Wisdom (Communities)

- [r/systems (Reddit)](https://reddit.com/r/systems)
  High-signal community for systems programming, storage engines, filesystems, and databases. Use for: discussions on storage engine performance, crash consistency, and filesystem trade-offs.
- [Kernel Newbies & Linux Kernel Documentation](https://kernelnewbies.org)
  Community and resources around Linux filesystem internals and Virtual Filesystem (VFS) semantics. Use for: deep dives into inode allocation, dentry caching, and page cache behavior.
