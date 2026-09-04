# Encrypted Sync Model

Each accepted mutation receives a monotonically increasing change sequence. Clients persist an opaque cursor representing the last applied sequence and request changes after that cursor.

## Rules

- Item heads are mutable pointers; revisions are immutable.
- A write supplies `expected_revision`; a mismatch returns `409 conflict`.
- Deletes create tombstones and never silently erase sync history.
- Change entries carry identifiers, operation, revision, and timestamps—never plaintext.
- Clients download the immutable revision ciphertext referenced by a change.
- An `Idempotency-Key` is unique per identity and operation for 24 hours.
- Batch operations are atomic per workspace unless explicitly marked best-effort.
- Cursor retention and snapshot recovery are defined before beta.

## Conflict behavior

The server never merges vault plaintext. A conflicting encrypted revision is retained as a conflict record and resolved by an authorized client after local decryption.
