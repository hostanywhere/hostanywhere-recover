package main

// These tests re-implement the HostAnywhere client-side ENCRYPTION exactly as
// the iOS/Android apps do it (Crypto.swift / StreamingCrypto.swift):
// convergent DEK = HMAC-SHA256(master, SHA256(plaintext)), deterministic IVs
// via domain-separated HMACs, HAE1 single-shot and HAE2 1 MB chunked framing.
// A passing round-trip therefore verifies this tool against the real wire
// formats, not against itself.

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func deriveHAE(master, plaintext []byte, v2 bool) (dek, dekIV, contentIV []byte) {
	pHash := sha256.Sum256(plaintext)
	m := hmac.New(sha256.New, master)
	m.Write(pHash[:])
	dek = m.Sum(nil)

	m = hmac.New(sha256.New, master)
	m.Write([]byte("dek-iv"))
	m.Write(pHash[:])
	dekIV = m.Sum(nil)[:12]

	label := "content-iv"
	if v2 {
		label = "content-iv-v2"
	}
	m = hmac.New(sha256.New, dek)
	m.Write([]byte(label))
	m.Write(pHash[:])
	contentIV = m.Sum(nil)[:12]
	return
}

func encryptHAE1(master, plaintext []byte, t *testing.T) []byte {
	dek, dekIV, contentIV := deriveHAE(master, plaintext, false)
	mg, _ := newGCM(master)
	wrapped := mg.Seal(nil, dekIV, dek, nil) // 32+16
	dg, _ := newGCM(dek)
	body := dg.Seal(nil, contentIV, plaintext, nil)

	var out bytes.Buffer
	out.WriteString("HAE1")
	out.WriteByte(1)    // ver
	out.WriteByte(0x01) // flags
	out.Write(dekIV)
	out.Write(wrapped)
	out.Write(contentIV)
	out.Write(body)
	return out.Bytes()
}

func encryptHAE2(master, plaintext []byte, chunkSize int, t *testing.T) []byte {
	dek, dekIV, seed := deriveHAE(master, plaintext, true)
	mg, _ := newGCM(master)
	wrapped := mg.Seal(nil, dekIV, dek, nil)
	dg, _ := newGCM(dek)

	var out bytes.Buffer
	out.WriteString("HAE2")
	out.WriteByte(2)
	out.WriteByte(0x01)
	out.Write(dekIV)
	out.Write(wrapped)
	out.Write(seed)

	var index uint64
	for off := 0; off < len(plaintext); off += chunkSize {
		end := off + chunkSize
		if end > len(plaintext) {
			end = len(plaintext)
		}
		iv := make([]byte, 12)
		copy(iv, seed)
		var idxBE [8]byte
		binary.BigEndian.PutUint64(idxBE[:], index)
		for i := 0; i < 8; i++ {
			iv[4+i] ^= idxBE[i]
		}
		sealed := dg.Seal(nil, iv, plaintext[off:end], nil) // ct || tag
		ct, tag := sealed[:len(sealed)-16], sealed[len(sealed)-16:]
		var lenBE [4]byte
		binary.BigEndian.PutUint32(lenBE[:], uint32(len(ct)))
		out.Write(lenBE[:])
		out.Write(ct)
		out.Write(tag)
		index++
	}
	out.Write([]byte{0, 0, 0, 0})
	return out.Bytes()
}

func TestHAE1RoundTrip(t *testing.T) {
	master := make([]byte, 32)
	rand.Read(master)
	plain := []byte("the ISP, caught red-handed")
	wire := encryptHAE1(master, plain, t)

	got, err := decryptHAE1(wire[:headerLen], wire[headerLen:], master)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("plaintext mismatch")
	}
}

func TestHAE2RoundTrip(t *testing.T) {
	master := make([]byte, 32)
	rand.Read(master)
	// Multi-chunk with a ragged tail: 2.5 chunks at a small chunk size.
	plain := make([]byte, 2560)
	rand.Read(plain)
	wire := encryptHAE2(master, plain, 1024, t)

	var out bytes.Buffer
	if err := decryptHAE2(wire[:headerLen], bytes.NewReader(wire[headerLen:]), master, &out); err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(out.Bytes(), plain) {
		t.Fatalf("plaintext mismatch")
	}
}

func TestHAE2WrongKeyFails(t *testing.T) {
	master := make([]byte, 32)
	rand.Read(master)
	wrong := make([]byte, 32)
	rand.Read(wrong)
	wire := encryptHAE2(master, []byte("secret"), 1024, t)
	var out bytes.Buffer
	if err := decryptHAE2(wire[:headerLen], bytes.NewReader(wire[headerLen:]), wrong, &out); err == nil {
		t.Fatal("expected auth failure with wrong key")
	}
}

func TestRecoveryCodeRoundTrip(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	code := encodeRecoveryCode(key)
	if got := len(code) - bytes.Count([]byte(code), []byte("-")); got != 52 {
		t.Fatalf("code length %d, want 52", got)
	}
	dec, err := decodeRecoveryCode(code)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !bytes.Equal(dec, key) {
		t.Fatal("round-trip mismatch")
	}
	// Tolerance: lowercase, spaces, Crockford aliases.
	sloppy := " " + string(bytes.ToLower([]byte(code))) + "\n"
	sloppy = string(bytes.ReplaceAll([]byte(sloppy), []byte("1"), []byte("l")))
	sloppy = string(bytes.ReplaceAll([]byte(sloppy), []byte("0"), []byte("o")))
	dec2, err := decodeRecoveryCode(sloppy)
	if err != nil {
		t.Fatalf("sloppy decode: %v", err)
	}
	if !bytes.Equal(dec2, key) {
		t.Fatal("sloppy round-trip mismatch")
	}
}

func TestFilenameToken(t *testing.T) {
	master := make([]byte, 32)
	rand.Read(master)
	meta, _ := json.Marshal(map[string]string{"fn": "vacation.jpg", "oid": "abc"})
	g, _ := newGCM(master)
	iv := make([]byte, 12)
	rand.Read(iv)
	sealed := g.Seal(nil, iv, meta, nil)
	token := "enc:" + base64.StdEncoding.EncodeToString(append(append([]byte{}, iv...), sealed...))

	if got := decryptName(token, master); got != "vacation.jpg" {
		t.Fatalf("decryptName = %q, want vacation.jpg", got)
	}
	if got := decryptName("plain-name.pdf", master); got != "plain-name.pdf" {
		t.Fatalf("plain name mangled: %q", got)
	}
}

// End-to-end: a fake storage root with HAE1 + HAE2 + legacy blobs and no
// index; then run recoverBlob against each the way main does.
func TestEndToEndNoIndex(t *testing.T) {
	master := make([]byte, 32)
	rand.Read(master)
	root := t.TempDir()
	outDir := filepath.Join(root, "out")

	jpeg := append([]byte{0xFF, 0xD8, 0xFF, 0xE0}, bytes.Repeat([]byte("x"), 100)...)
	cases := map[string][]byte{
		"hae1": encryptHAE1(master, jpeg, t),
		"hae2": encryptHAE2(master, jpeg, 64, t),
		"raw":  jpeg,
	}
	for name, wire := range cases {
		sum := sha256.Sum256(wire)
		sha := make([]byte, 64)
		const hexd = "0123456789abcdef"
		for i, b := range sum {
			sha[i*2], sha[i*2+1] = hexd[b>>4], hexd[b&0xF]
		}
		p := filepath.Join(root, string(sha))
		os.WriteFile(p, wire, 0o600)

		st, err := recoverBlob(p, string(sha), blobMeta{}, master, outDir)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		want := stDecrypted
		if name == "raw" {
			want = stPassthrough
		}
		if st != want {
			t.Fatalf("%s: status %v, want %v", name, st, want)
		}
	}
	// All three decode to the same JPEG → sniffed .jpg names, deduped.
	entries, _ := os.ReadDir(filepath.Join(outDir, "other"))
	if len(entries) != 3 {
		t.Fatalf("expected 3 recovered files, got %d", len(entries))
	}
	for _, e := range entries {
		b, _ := os.ReadFile(filepath.Join(outDir, "other", e.Name()))
		if !bytes.Equal(b, jpeg) {
			t.Fatalf("%s: recovered bytes differ", e.Name())
		}
		if filepath.Ext(e.Name()) != ".jpg" {
			t.Fatalf("%s: expected sniffed .jpg extension", e.Name())
		}
	}
}
