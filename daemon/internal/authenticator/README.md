The authenticator imports the kernel's v1 and v2 metadata layouts, including
both historical CRC32 variants. Migration preserves credential IDs, raw P-256
keys, user handles, signature counts, HMAC secrets, and the stored AAGUID.
The raw scalar and x/y fields are big-endian bytes, despite the little-endian
metadata header.

A new store uses the implementation AAGUID
`8dc94f6e-7524-4a6f-988e-23b7116d5042`. AAGUID is a model identifier, not key
material. An imported kernel store keeps its old AAGUID until an explicitly
approved authenticator reset; reset removes all credentials and starts a new
store with the fixed implementation AAGUID.

Every credential operation requires local verification. Assertions always set
UV, and protocol-one hmac-secret consequently uses the legacy secret as
CredRandomWithUV. Silent assertions and client PIN operations are unsupported;
the clientPIN command supports only getKeyAgreement for hmac-secret.

Store changes use a mode-0600 temporary file, file fsync, rename, and directory
fsync before publishing a response. An I/O failure blocks further mutations
until restart. If cancellation or an uncertain directory sync happens after a
rename, the file can contain an unannounced credential or an advanced counter;
the engine releases no success response, and restart reloads the durable state.
