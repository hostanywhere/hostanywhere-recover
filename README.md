# hostanywhere-recover

Standalone, open-source decryption tool for [HostAnywhere](https://hostanywhere.io) backups.

This tool exists to answer one question honestly: **what happens to your backups if HostAnywhere disappears?** Answer: nothing. Your files are on your own storage computer, your recovery code is a copy of your key that doesn't depend on your account, and this tool turns those two things back into your files — offline, with no HostAnywhere servers, accounts, or apps involved.

One honest caveat: **export your recovery code while the service is running** — it's a copy of a key that otherwise lives with your account. Exporting takes a minute and never expires. And for the record: if HostAnywhere ever winds down, users get advance notice and time to export codes and verify their backups first — not a surprise shutdown.

## Usage

```sh
hostanywhere-recover -code ABCD-EFGH-JKMN-... -in /path/to/storage-folder -out ./recovered
```

- `-code` — your 52-character recovery code, exported from the mobile apps (Backups → Settings → **Export recovery code**) or the dashboard (Settings → **Your exit path**). Dashes, spaces, and lowercase are all accepted. If omitted, you'll be prompted.
- `-in` — your HostAnywhere storage folder (the one containing `blobs/` and `.index.db`), or any directory of blob files.
- `-out` — where decrypted files go (default `./hostanywhere-recovered`), organized by category (photos, contacts, …).

When the storage folder's index database is present, files come back with their **original names**. Without it, files are named by content hash with a best-effort extension.

## Build

```sh
go build .
```

That's it — pure Go, no CGO, builds on macOS, Windows, and Linux.

## What it understands

- **HAE1** — the single-shot encrypted blob format (AES-256-GCM, per-file wrapped data-encryption key).
- **HAE2** — the chunked streaming format used for large files (1 MB independently-authenticated AES-256-GCM chunks).
- **Encrypted filenames** — the sealed metadata tokens stored in the index.
- **Legacy blobs** — anything from before encryption shipped is copied through unchanged.

The format details are documented in the source (`main.go`), and the test suite (`main_test.go`) independently re-implements the encryption side of both formats to verify this tool against the real wire formats.

## Security notes

- Your recovery code **is** your master key. Anyone with the code and your blob files can read your backups. Store it like a password.
- This tool never touches the network. You can verify that by reading it — that's the point of it being open.

## License

MIT
