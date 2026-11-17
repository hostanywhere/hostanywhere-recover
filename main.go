// hostanywhere-recover — standalone decryption tool for HostAnywhere backups.
//
// This tool exists so that your backups never depend on HostAnywhere the
// company. Given (1) your recovery code and (2) the blob directory from any
// of your storage machines, it decrypts every backed-up file to a normal
// folder — no HostAnywhere servers, accounts, or software involved.
//
// Usage:
//
//	hostanywhere-recover -code ABCD-EFGH-... -in /path/to/storage-root -out ./recovered
//
// where -in is either a HostAnywhere storage root (the folder that contains
// "blobs/" and ".index.db") or a bare directory of blob files. The index
// database, when present, restores original filenames and categories; without
// it files are named by content hash with a best-effort extension.
//
// Wire formats (produced by the HostAnywhere mobile/desktop clients):
//
//	HAE1 (single-shot):
//	  magic(4)="HAE1" ver(1)=1 flags(1) dek_iv(12) wrapped_dek(48)
//	  content_iv(12) ciphertext+tag(N+16)
//	HAE2 (chunked streaming):
//	  magic(4)="HAE2" ver(1)=2 flags(1) dek_iv(12) wrapped_dek(48)
//	  content_iv_seed(12) then repeated [chunk_len(4,BE) ct(chunk_len) tag(16)]
//	  terminated by chunk_len=0. Per-chunk nonce: seed with bytes [4..12)
//	  XORed with the big-endian chunk index.
//
// In both formats wrapped_dek = AES-256-GCM(master_key, dek) and content is
// AES-256-GCM under the dek. Anything without a recognized magic is a legacy
// pre-encryption blob and is copied through unchanged.
//
// Filenames: the index stores either a plaintext name or an "enc:" token =
// base64(iv(12) | ciphertext | tag(16)) of a JSON object {"fn": name, ...}
// sealed with the master key.
//
// Recovery code: the 32-byte master key in Crockford base32 (52 chars,
// usually dash-grouped). Decoding tolerates dashes, spaces, lowercase, and
// the Crockford aliases O→0, I→1, L→1.
package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	_ "modernc.org/sqlite"
)

const (
	headerLen = 78 // magic(4)+ver(1)+flags(1)+dek_iv(12)+wrapped_dek(48)+iv/seed(12)
	tagLen    = 16
)

func main() {
	code := flag.String("code", "", "recovery code (52-char, dashes optional); prompted for if omitted")
	in := flag.String("in", "", "storage root (contains blobs/ and .index.db) or a directory of blob files")
	out := flag.String("out", "hostanywhere-recovered", "output directory for decrypted files")
	flag.Parse()

	if *in == "" {
		fmt.Fprintln(os.Stderr, "hostanywhere-recover: -in is required (your storage folder)")
		flag.Usage()
		os.Exit(2)
	}
	if *code == "" {
		fmt.Fprint(os.Stderr, "Recovery code: ")
		r := make([]byte, 256)
		n, _ := os.Stdin.Read(r)
		*code = string(r[:n])
	}

	master, err := decodeRecoveryCode(*code)
	if err != nil {
		fatal("invalid recovery code: %v", err)
	}

	blobDir := *in
	indexPath := ""
	if st, err := os.Stat(filepath.Join(*in, "blobs")); err == nil && st.IsDir() {
		blobDir = filepath.Join(*in, "blobs")
		if _, err := os.Stat(filepath.Join(*in, ".index.db")); err == nil {
			indexPath = filepath.Join(*in, ".index.db")
		}
	}

	names := map[string]blobMeta{}
	if indexPath != "" {
		names, err = loadIndex(indexPath, master)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: could not read index (%v) — files will be hash-named\n", err)
		} else {
			fmt.Printf("index: %d file records\n", len(names))
		}
	} else {
		fmt.Println("no index database found — files will be hash-named with sniffed extensions")
	}

	if err := os.MkdirAll(*out, 0o755); err != nil {
		fatal("create output dir: %v", err)
	}

	var ok, passthrough, failed, skipped int
	err = filepath.WalkDir(blobDir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		base := filepath.Base(path)
		if !isHex64(base) {
			skipped++
			return nil
		}
		meta := names[base]
		status, derr := recoverBlob(path, base, meta, master, *out)
		switch status {
		case stDecrypted:
			ok++
		case stPassthrough:
			passthrough++
		case stFailed:
			failed++
			fmt.Fprintf(os.Stderr, "FAILED %s: %v\n", base[:12], derr)
		}
		// Wrong-code early exit: nothing has decrypted and several blobs failed.
		if failed >= 5 && ok == 0 {
			return errors.New("the recovery code does not match these blobs (every attempt failed authentication) — double-check the code")
		}
		return nil
	})
	if err != nil {
		fatal("%v", err)
	}

	fmt.Printf("\ndone: %d decrypted, %d legacy copied, %d failed, %d non-blob files skipped\n",
		ok, passthrough, failed, skipped)
	fmt.Printf("recovered files are in: %s\n", *out)
	if failed > 0 {
		os.Exit(1)
	}
}

type blobMeta struct {
	filename string
	kind     string
}

type status int

const (
	stDecrypted status = iota
	stPassthrough
	stFailed
)

// recoverBlob decrypts (or passes through) one blob file and writes the
// result into outDir, organized by kind when known.
func recoverBlob(path, sha string, meta blobMeta, master []byte, outDir string) (status, error) {
	f, err := os.Open(path)
	if err != nil {
		return stFailed, err
	}
	defer f.Close()

	head := make([]byte, headerLen)
	n, _ := io.ReadFull(f, head)
	head = head[:n]

	var plain io.Reader
	var st status
	switch {
	case n == headerLen && bytes.Equal(head[:4], []byte("HAE1")):
		body, err := io.ReadAll(f)
		if err != nil {
			return stFailed, err
		}
		pt, err := decryptHAE1(head, body, master)
		if err != nil {
			return stFailed, err
		}
		plain, st = bytes.NewReader(pt), stDecrypted
	case n == headerLen && bytes.Equal(head[:4], []byte("HAE2")):
		pr, pw := io.Pipe()
		go func() { pw.CloseWithError(decryptHAE2(head, f, master, pw)) }()
		plain, st = pr, stDecrypted
	default:
		// Legacy plaintext blob — copy through unchanged.
		plain, st = io.MultiReader(bytes.NewReader(head), f), stPassthrough
	}

	// Decide the output name. Sniff an extension from the first bytes when
	// the index gave us nothing.
	br := newPeeker(plain)
	name := meta.filename
	if name == "" {
		name = sha + sniffExt(br.peek(12))
	}
	sub := meta.kind
	if sub == "" {
		sub = "other"
	}
	destDir := filepath.Join(outDir, sanitize(sub))
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return stFailed, err
	}
	dest := uniquePath(filepath.Join(destDir, sanitize(name)))

	outF, err := os.Create(dest)
	if err != nil {
		return stFailed, err
	}
	defer outF.Close()
	if _, err := io.Copy(outF, br); err != nil {
		os.Remove(dest) // don't leave a truncated file on auth failure mid-stream
		return stFailed, err
	}
	return st, nil
}

// ── wire formats ───────────────────────────────────────────────────────────

// unwrapDEK opens wrapped_dek (32-byte ciphertext + 16-byte tag) with the
// master key and the dek_iv from the header.
func unwrapDEK(head, master []byte) ([]byte, error) {
	dekIV := head[6:18]
	wrapped := head[18:66]
	aead, err := newGCM(master)
	if err != nil {
		return nil, err
	}
	dek, err := aead.Open(nil, dekIV, wrapped, nil)
	if err != nil {
		return nil, fmt.Errorf("DEK unwrap failed (wrong recovery code?): %w", err)
	}
	return dek, nil
}

func decryptHAE1(head, body, master []byte) ([]byte, error) {
	dek, err := unwrapDEK(head, master)
	if err != nil {
		return nil, err
	}
	contentIV := head[66:78]
	aead, err := newGCM(dek)
	if err != nil {
		return nil, err
	}
	pt, err := aead.Open(nil, contentIV, body, nil)
	if err != nil {
		return nil, fmt.Errorf("content decrypt failed: %w", err)
	}
	return pt, nil
}

// decryptHAE2 streams the chunked format: per-chunk nonce = seed with bytes
// [4..12) XORed with the big-endian chunk index.
func decryptHAE2(head []byte, r io.Reader, master []byte, w io.Writer) error {
	dek, err := unwrapDEK(head, master)
	if err != nil {
		return err
	}
	seed := head[66:78]
	aead, err := newGCM(dek)
	if err != nil {
		return err
	}

	var lenBuf [4]byte
	var index uint64
	for {
		if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
			if err == io.EOF {
				return nil // tolerated: blob truncated exactly at a chunk boundary
			}
			return fmt.Errorf("chunk %d: read length: %w", index, err)
		}
		chunkLen := binary.BigEndian.Uint32(lenBuf[:])
		if chunkLen == 0 {
			return nil // terminator
		}
		buf := make([]byte, int(chunkLen)+tagLen)
		if _, err := io.ReadFull(r, buf); err != nil {
			return fmt.Errorf("chunk %d: read body: %w", index, err)
		}
		iv := make([]byte, 12)
		copy(iv, seed)
		var idxBE [8]byte
		binary.BigEndian.PutUint64(idxBE[:], index)
		for i := 0; i < 8; i++ {
			iv[4+i] ^= idxBE[i]
		}
		pt, err := aead.Open(nil, iv, buf, nil)
		if err != nil {
			return fmt.Errorf("chunk %d: decrypt failed: %w", index, err)
		}
		if _, err := w.Write(pt); err != nil {
			return err
		}
		index++
	}
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// ── index / filenames ──────────────────────────────────────────────────────

// loadIndex reads sha → (filename, kind) from the storage server's SQLite
// index, decrypting "enc:" filename tokens with the master key.
func loadIndex(path string, master []byte) (map[string]blobMeta, error) {
	db, err := sql.Open("sqlite", path+"?mode=ro&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, err
	}
	defer db.Close()

	rows, err := db.Query(`SELECT sha256, COALESCE(filename,''), COALESCE(kind,'') FROM blobs`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := map[string]blobMeta{}
	for rows.Next() {
		var sha, fn, kind string
		if err := rows.Scan(&sha, &fn, &kind); err != nil {
			return nil, err
		}
		out[sha] = blobMeta{filename: decryptName(fn, master), kind: kind}
	}
	return out, rows.Err()
}

// decryptName resolves an index filename value: "enc:" tokens are sealed
// JSON ({"fn": name}); anything else is already a plain name.
func decryptName(v string, master []byte) string {
	if !strings.HasPrefix(v, "enc:") {
		return v
	}
	raw, err := base64.StdEncoding.DecodeString(v[4:])
	if err != nil || len(raw) <= 12+tagLen {
		return ""
	}
	aead, err := newGCM(master)
	if err != nil {
		return ""
	}
	pt, err := aead.Open(nil, raw[:12], raw[12:], nil)
	if err != nil {
		return ""
	}
	var obj map[string]string
	if json.Unmarshal(pt, &obj) != nil {
		return ""
	}
	return obj["fn"]
}

// ── recovery code ──────────────────────────────────────────────────────────

var crockford = func() map[rune]uint64 {
	m := map[rune]uint64{}
	for i, c := range "0123456789ABCDEFGHJKMNPQRSTVWXYZ" {
		m[c] = uint64(i)
	}
	return m
}()

// decodeRecoveryCode decodes a Crockford base32 recovery code to the 32-byte
// master key, tolerating dashes, spaces, case, and O/I/L aliases.
func decodeRecoveryCode(raw string) ([]byte, error) {
	cleaned := strings.ToUpper(strings.TrimSpace(raw))
	cleaned = strings.NewReplacer("-", "", " ", "", "\n", "", "\r", "", "\t", "",
		"O", "0", "I", "1", "L", "1").Replace(cleaned)
	var bits, nBits uint64
	out := make([]byte, 0, 32)
	for _, c := range cleaned {
		v, okc := crockford[c]
		if !okc {
			return nil, fmt.Errorf("invalid character %q", c)
		}
		bits = bits<<5 | v
		nBits += 5
		for nBits >= 8 {
			nBits -= 8
			out = append(out, byte(bits>>nBits))
		}
	}
	if len(out) != 32 {
		return nil, fmt.Errorf("decodes to %d bytes, want 32 (code should be 52 characters)", len(out))
	}
	return out, nil
}

// encodeRecoveryCode is the inverse, used by tests to verify round-trips
// against the mobile apps' encoder.
func encodeRecoveryCode(key []byte) string {
	const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	var bits, nBits uint64
	var sb strings.Builder
	for _, b := range key {
		bits = bits<<8 | uint64(b)
		nBits += 8
		for nBits >= 5 {
			nBits -= 5
			sb.WriteByte(alphabet[(bits>>nBits)&0x1F])
		}
	}
	if nBits > 0 {
		sb.WriteByte(alphabet[(bits<<(5-nBits))&0x1F])
	}
	s := sb.String()
	var groups []string
	for i := 0; i < len(s); i += 4 {
		end := i + 4
		if end > len(s) {
			end = len(s)
		}
		groups = append(groups, s[i:end])
	}
	return strings.Join(groups, "-")
}

// ── small helpers ──────────────────────────────────────────────────────────

func isHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// sniffExt guesses a file extension from magic bytes — only used when the
// index gave us no filename.
func sniffExt(b []byte) string {
	switch {
	case len(b) >= 3 && b[0] == 0xFF && b[1] == 0xD8 && b[2] == 0xFF:
		return ".jpg"
	case len(b) >= 8 && bytes.Equal(b[:8], []byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A}):
		return ".png"
	case len(b) >= 12 && bytes.Equal(b[4:8], []byte("ftyp")):
		sub := string(b[8:12])
		if strings.HasPrefix(sub, "hei") || strings.HasPrefix(sub, "mif") {
			return ".heic"
		}
		if sub == "qt  " {
			return ".mov"
		}
		return ".mp4"
	case len(b) >= 4 && bytes.Equal(b[:4], []byte("%PDF")):
		return ".pdf"
	case len(b) >= 6 && bytes.Equal(b[:6], []byte("GIF87a")) || len(b) >= 6 && bytes.Equal(b[:6], []byte("GIF89a")):
		return ".gif"
	case len(b) >= 12 && bytes.Equal(b[:4], []byte("RIFF")) && bytes.Equal(b[8:12], []byte("WEBP")):
		return ".webp"
	case len(b) >= 5 && bytes.Equal(b[:5], []byte("BEGIN")):
		return ".vcf" // contacts/calendar exports start with BEGIN:VCARD / BEGIN:VCALENDAR
	case len(b) >= 1 && (b[0] == '{' || b[0] == '['):
		return ".json"
	default:
		return ".bin"
	}
}

// sanitize keeps a name safe as a single path element.
func sanitize(name string) string {
	name = filepath.Base(strings.ReplaceAll(name, "\\", "/"))
	name = strings.Map(func(r rune) rune {
		if r < 0x20 || r == ':' {
			return '_'
		}
		return r
	}, name)
	if name == "" || name == "." || name == ".." {
		return "_"
	}
	return name
}

// uniquePath appends " (2)", " (3)"… before the extension until the path is free.
func uniquePath(p string) string {
	if _, err := os.Stat(p); os.IsNotExist(err) {
		return p
	}
	ext := filepath.Ext(p)
	stem := strings.TrimSuffix(p, ext)
	for i := 2; ; i++ {
		cand := fmt.Sprintf("%s (%d)%s", stem, i, ext)
		if _, err := os.Stat(cand); os.IsNotExist(err) {
			return cand
		}
	}
}

// peeker lets us sniff the first bytes of a stream and still copy all of it.
type peeker struct {
	r    io.Reader
	head []byte
	done bool
}

func newPeeker(r io.Reader) *peeker { return &peeker{r: r} }

func (p *peeker) peek(n int) []byte {
	buf := make([]byte, n)
	m, _ := io.ReadFull(p.r, buf)
	p.head = buf[:m]
	return p.head
}

func (p *peeker) Read(b []byte) (int, error) {
	if !p.done && len(p.head) > 0 {
		n := copy(b, p.head)
		p.head = p.head[n:]
		if len(p.head) == 0 {
			p.done = true
		}
		return n, nil
	}
	return p.r.Read(b)
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "hostanywhere-recover: "+format+"\n", args...)
	os.Exit(1)
}
