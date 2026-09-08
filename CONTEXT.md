# Object Storage

A standalone, S3-compatible object storage service built with Java Spring Boot, backed by local filesystem storage and embedded database metadata, paired with a zero-dependency Java client SDK.

## Language

**Bucket**:
A uniquely named top-level container for storing objects.
_Avoid_: Folder, directory, container

**Object**:
An entity consisting of raw payload bytes and associated metadata, identified by a key within a bucket.
_Avoid_: File, blob, item, record

**Key**:
The unique UTF-8 string identifier for an object within a specific bucket.
_Avoid_: Filepath, path, object name

**Payload**:
The raw binary stream of bytes representing the data content of an object.
_Avoid_: Body, data, blob

**Metadata**:
System attributes (size, ETag/checksum, content type, creation timestamp) and custom key-value pairs describing an object.
_Avoid_: Properties, attributes, headers

**Storage Engine**:
The disk-based subsystem responsible for persisting and streaming raw object payloads.
_Avoid_: Disk manager, file store, filesystem service

**Metadata Store**:
The embedded database tracking bucket registrations, object keys, and metadata records.
_Avoid_: Database, catalog, registry

**Client SDK**:
The standalone, zero-dependency Java HTTP client library used by external applications to consume the object storage service.
_Avoid_: Client library, driver, connector
