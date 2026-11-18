# HostAnywhere backup format — specification

This document specifies, byte for byte, how HostAnywhere clients encrypt
backed-up files, how encrypted blobs are laid out on a storage machine, and
what the recovery code is. It exists so that anyone can audit the design and
write an independent decryptor; `main.go` in this repository is one such
implementation, and the known-answer vectors at the end let you verify any
other.

Everything here describes what the shipped clients actually do. Where the
design has limits, they are stated plainly rather than papered over.

## 1. Actors and trust model

Three parties touch a backup:

| Party | Holds | Does NOT hold |
|---|---|---|
| **Your device** (phone/laptop running the app) | plaintext, master key | — |
| **Storage machine(s)** (your own computers, or a friend's, running the HostAnywhere storage server) | ciphertext blobs + index | master key, plaintext |
| **Control plane** (hostanywhere.io, or your self-hosted server) | an escrowed copy of the master key | your files, in any form |

The core property: **the keys and the data are never held by the same
party.** Storage machines — including a friend's machine replicating your
blobs — see only ciphertext. The control plane can recover your key but has
no ciphertext to use it on.

### What this is, and is not

This is the **standard-tier** model, the same shape as iCloud Standard or
Google Photos: the service escrows the key so that "sign in on a new phone"
is all it takes to restore. It is **not end-to-end encryption** — the
control-plane operator who also obtained your blobs (e.g. by seizing both
your account and a storage machine) could decrypt them. We say this plainly
because the recovery code exists precisely to remove even that dependency:

### The exit path

Exporting your recovery code (Backups → Settings → Export recovery code)
hands you the master key itself. From that moment, **recovery code + blob
directory = your data**, with no HostAnywhere account, server, or goodwill
involved. If HostAnywhere winds down, users will be given time to export
codes and data first — but a user who exported the code already needs
nothing from us. That is the scenario this repository's tool exists for.

### Convergent encryption, stated honestly

The per-file key (DEK, §3) is derived as `HMAC-SHA256(master_key,
SHA256(plaintext))`. Consequences:

- The same file encrypted twice by your devices produces **identical
  ciphertext**, so storage machines deduplicate without seeing plaintext.
- Encryption is deterministic **only under your master key**. Unlike plain
  convergent encryption (key = hash of plaintext), an outsider cannot run a
  confirmation-of-file attack — deriving the DEK requires the master key.
- Anyone who *does* hold the master key can confirm whether a given exact
  file is among your blobs without decrypting everything. This is inherent
  to keyed-convergent designs and is the price of dedup.

### Nonce safety

All encryption is AES-256-GCM with 12-byte nonces, which is only safe if a
(key, nonce) pair never encrypts two different messages. The derivation
makes this structural rather than probabilistic:

- The DEK-wrap nonce `dek_iv` is `HMAC(master, "dek-iv" ‖ SHA256(pt))[0:12]`:
  two different plaintexts give different nonces; the same plaintext gives
  the same nonce *wrapping the same DEK to the same bytes* — a repeat of an
  identical message, which leaks nothing new.
- Content nonces are derived under the DEK itself (`HMAC(dek, label ‖
  SHA256(pt))`), and each DEK only ever encrypts the one plaintext it was
  derived from (plus, in HAE2, chunk indices XORed into distinct nonces).

## 2. Recovery code

The recovery code **is** the 32-byte master key, encoded in [Crockford
base32](https://www.crockford.com/base32.html):

- Alphabet: `0123456789ABCDEFGHJKMNPQRSTVWXYZ` (no `I`, `L`, `O`, `U`).
- 32 bytes → 52 characters (the final character carries 4 padding bits of
  zero, per standard base32 left-alignment).
- Displayed in dash-separated groups of 4: `XXXX-XXXX-…` (13 groups).

Decoders MUST accept: lowercase, embedded dashes/spaces/newlines, and the
Crockford aliases `O→0`, `I→1`, `L→1`. Encoders MUST emit only the canonical
alphabet. There is no checksum character; a mistyped code simply fails GCM
authentication on every blob (§6).

## 3. Key hierarchy

```
master_key (32 B)                      — generated client-side (CSPRNG) on
  │                                      first backup; escrowed to the control
  │                                      plane; cached in the platform keystore
  │                                      (iOS: iCloud-synced Keychain)
  ├── per-blob DEK (32 B)   = HMAC-SHA256(master_key, SHA256(plaintext))
  │     └── encrypts file content (AES-256-GCM)
  ├── wraps each DEK         (AES-256-GCM, §4 header)
  └── seals filename tokens  (AES-256-GCM, §5)
```

Derivations (all HMAC-SHA256, truncation = first 12 bytes):

| Value | Formula |
|---|---|
| `dek` | `HMAC(master_key, SHA256(pt))` (full 32 bytes) |
| `dek_iv` | `HMAC(master_key, "dek-iv" ‖ SHA256(pt))[0:12]` |
| `content_iv` (HAE1) | `HMAC(dek, "content-iv" ‖ SHA256(pt))[0:12]` |
| `content_iv_seed` (HAE2) | `HMAC(dek, "content-iv-v2" ‖ SHA256(pt))[0:12]` |

`wrapped_dek = AES-256-GCM-Seal(master_key, dek_iv, dek)` → 32 ciphertext +
16 tag = 48 bytes. No AAD is used anywhere in the format.

## 4. Blob wire formats

Every encrypted blob starts with a 78-byte header:

```
offset  size  field
0       4     magic        "HAE1" or "HAE2" (ASCII)
4       1     version      1 (HAE1) / 2 (HAE2)
5       1     flags        bit 0: filename stored encrypted in the index
6       12    dek_iv
18      48    wrapped_dek
66      12    content_iv (HAE1) / content_iv_seed (HAE2)
```

All multi-byte integers anywhere in the format are **big-endian**.

### HAE1 — single-shot

Header, then one GCM sealed box:

```
ciphertext ‖ tag(16)  =  AES-256-GCM-Seal(dek, content_iv, plaintext)
```

### HAE2 — chunked streaming

Header, then repeated chunks, then a terminator:

```
repeat:
  chunk_len (4, BE)        — ciphertext length, > 0
  ciphertext (chunk_len)
  tag (16)
terminator:
  chunk_len = 0
```

Per-chunk nonce for chunk *i* (0-based):

```
nonce = content_iv_seed
nonce[4..12) ^= big_endian_uint64(i)
```

Each chunk is an independent `AES-256-GCM-Seal(dek, nonce, chunk_plaintext)`.
Producers currently emit 256 KiB plaintext chunks (iOS streaming path), but
decoders MUST accept any chunk size — the framing is self-describing.
Chunked-with-per-chunk-tags (rather than one giant GCM message) means
truncation and reordering are detected per chunk and decryption runs in
constant memory.

Writers: iOS emits HAE1 (small items) and HAE2 (streamed media); Android
emits HAE1. Decoders MUST support both.

### Legacy blobs

Blobs written before encryption shipped have neither magic. Anything not
starting with `HAE1`/`HAE2` is plaintext and is passed through unchanged by
recovery tools.

## 5. Storage layout and the index

A storage machine's root contains:

```
<root>/blobs/<sha[0:2]>/<sha[2:4]>/<sha>    — blob files
<root>/.index.db                            — SQLite index
```

`<sha>` is the lowercase hex **SHA-256 of the blob file as stored** (i.e. of
the ciphertext for encrypted blobs, of the raw bytes for legacy blobs) — 64
hex characters. Storage machines can therefore verify blob integrity without
any keys.

The index tables a recovery tool needs:

```sql
CREATE TABLE blobs (
  sha256   TEXT PRIMARY KEY,   -- blob filename
  size     INTEGER NOT NULL,
  kind     TEXT,               -- photo | video | contact | calendar | health
                               --   | sms | calllog | apk | file
  filename TEXT                -- original name, possibly sealed (below)
  -- … bookkeeping columns a decryptor can ignore
);
```

A `filename` value either is the plain name, or starts with `enc:` followed
by `base64_std( iv(12) ‖ ciphertext ‖ tag(16) )` where the sealed payload is
UTF-8 JSON `{"fn": "<original name>", …}` encrypted with
`AES-256-GCM(master_key, iv)`. (Producers use a random `iv` per token.)

The index is a convenience, not a dependency: without it, blobs decrypt fine
and are named `<sha>` plus an extension sniffed from the decrypted bytes'
magic numbers.

## 6. Failure behavior

GCM authentication makes wrong keys loud: with an incorrect recovery code,
**every** DEK unwrap fails its tag check. A recovery tool SHOULD treat "N
consecutive failures, zero successes" (this implementation: N = 5) as
"wrong code" and stop, rather than plowing through terabytes. A *partial*
failure pattern (some blobs decrypt, some fail) indicates corrupt blobs, not
a wrong code. Tools MUST NOT emit partial plaintext for a chunk or blob
whose tag failed.

## 7. Known-answer test vectors

Generated with the master key `000102…1e1f` (bytes 0–31). Because all
derivation is deterministic (§3), a conforming **encryptor** must reproduce
these ciphertexts exactly, and a conforming **decryptor** must accept them.

**Master key (hex):**
```
000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
```

**Recovery code for that key:**
```
000G-40R4-0M30-E209-185G-R38E-1W81-24GK-2GAH-C5RR-34D1-P70X-3RFG
```

**Plaintext** (19 bytes): `hello hostanywhere\n`

**HAE1 blob (hex):**
```
48414531010129345c5f34514dccd9248f0729d828059b13e3f94cd4200e260f
5486c0f61bf326083113c51072dcc0b679c85865a8011c854f362c52efd33f41
63204363350f5b96dfaa4d748411797599075f872d1115ce055792089ac3e563
1781d91f1241b6a782d6fb79f847abaedb
```

**HAE2 blob, 8-byte chunks (hex)** — same key and plaintext, demonstrating
the chunk framing, nonce XOR, and terminator:
```
48414532020129345c5f34514dccd9248f0729d828059b13e3f94cd4200e260f
5486c0f61bf326083113c51072dcc0b679c85865a8011c854f362c52efd33f41
632056c0acd8ef2997b16d8054eb000000080ccff3006cb6efe405c7493b1227
0f3424abd2cde90b3b8100000008bbe68e112a39523c7e2174951777aaa1a3c2
521226657ea800000003a63b68d64579d5fb8d0acb3d153a6a8da95e24000000
00
```

**Filename token** (zero IV, used only for this vector; producers use random
IVs) — decrypts to `{"fn":"IMG_0001.HEIC"}`:
```
enc:AAAAAAAAAAAAAAAAdZ7TsJcWofRF7/YFKBygt5oGHxAK/AEu9qAPZ4RsL1ZkD8YloxM=
```

The test suite in `main_test.go` additionally re-implements the client
encryptors from this spec and round-trips randomized inputs through
`main.go`'s decryptor, so `go test ./...` checks an independent pairing of
the two sides.

## 8. Versioning

`magic` + `ver` identify the format. Any future change that is not
byte-compatible will use a new magic/version, and this spec will document
it; existing blobs are never rewritten. This document describes HAE1 v1 and
HAE2 v2 as produced by the current clients (iOS 1.0.9, Android 1.0.25);
neither format has changed since it was introduced.
