// chachacrypt.go
package main

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/term"
)

const (
	// File format / protocol constants
	magic         = "CCRYPT1\x00"
	formatVersion = 1

	// Crypto parameters
	keyLen       = 32            // bytes for AEAD key portion
	hmacKeyLen   = 32            // bytes for HMAC key portion
	derivedKeyLen = keyLen + hmacKeyLen

	saltLen      = 16
	baseNonceLen = 16 // we'll append 8-byte counter to this to make 24-byte nonce
	nonceSizeX   = chacha20poly1305.NonceSizeX

	// Chunking
	chunkDefault = 1 << 20        // 1 MiB
	chunkMin     = 1 << 12        // 4 KiB
	chunkMax     = 16 << 20       // 16 MiB

	// Parameter defaults and caps
	memoryKBDef  = 64 * 1024      // 64 MiB expressed in KB
	memoryKBMax  = 1024 * 1024    // 1 GiB in KB
	timeDef      = 3
	timeMax      = 12
	threadsMaxCap = 256

	// HMAC size
	hmacSize = sha256.Size

	// Files
	tmpPrefix = ".chachacrypt_tmp_"
)

var (
	// Channel holds temporary file paths to clean up on signal.
	tempFilesToRemove = make(chan string, 16)
	logger            = log.New(os.Stderr, "chachacrypt: ", log.LstdFlags)
)

// header represents the on-disk header (without trailing HMAC).
// Serialized layout:
// [1 byte version][len(magic) bytes magic][4 Time][4 MemoryKB][1 Threads][1 SaltLen][2 Reserved][Salt][BaseNonce]
type header struct {
	Version   uint8
	Time      uint32
	MemoryKB  uint32
	Threads   uint8
	SaltLen   uint8
	Reserved  uint16
	Salt      []byte
	BaseNonce []byte
}

// encryption options used by the CLI and internal functions.
type encryptOptions struct {
	Time       uint32
	MemoryKB   uint32
	Threads    uint8
	ChunkBytes int
}

func main() {
	setupSignalHandler()

	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "enc":
		enc(os.Args[2:])
	case "dec":
		dec(os.Args[2:])
	case "pw":
		pw(os.Args[2:])
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintln(os.Stderr, "unknown command:", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Println("Usage:")
	fmt.Println("  chachacrypt enc -i <in> -o <out> [-mem 65536] [-time 3] [-threads N] [-chunk 1048576] [-overwrite]")
	fmt.Println("  chachacrypt dec -i <in> -o <out> [-overwrite]")
	fmt.Println("  chachacrypt pw  -s <length>")
}

// setupSignalHandler removes temporary files on interrupt/terminate.
func setupSignalHandler() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		logger.Println("received interrupt; cleaning up temporary files")
		close(tempFilesToRemove)
		for p := range tempFilesToRemove {
			_ = os.Remove(p)
		}
		// brief pause before exiting to allow any deferred cleanup
		time.Sleep(50 * time.Millisecond)
		os.Exit(2)
	}()
}

func enc(args []string) {
	fs := flag.NewFlagSet("enc", flag.ExitOnError)
	in := fs.String("i", "", "input file")
	out := fs.String("o", "", "output file")
	mem := fs.Uint("mem", memoryKBDef, "argon2 memory in KB")
	tm := fs.Uint("time", timeDef, "argon2 iterations")
	thr := fs.Uint("threads", uint(runtime.NumCPU()), "argon2 parallelism")
	chunk := fs.Uint("chunk", chunkDefault, "chunk size in bytes")
	overwrite := fs.Bool("overwrite", false, "overwrite output if exists")
	_ = fs.Parse(args)

	if *in == "" || *out == "" {
		fmt.Fprintln(os.Stderr, "missing -i or -o")
		os.Exit(2)
	}
	if !*overwrite && fileExists(*out) {
		ok, err := confirm(fmt.Sprintf("Overwrite %s? [y/N]: ", *out))
		if err != nil {
			logger.Printf("prompt failed: %v", err)
			os.Exit(1)
		}
		if !ok {
			os.Exit(1)
		}
	}
	pw, err := readPassword("Password: ")
	if err != nil {
		logger.Fatalf("read password: %v", err)
	}
	if len(pw) == 0 {
		logger.Fatal("empty password")
	}

	opt := encryptOptions{
		Time:       uint32(*tm),
		MemoryKB:   uint32(*mem),
		Threads:    uint8(*thr),
		ChunkBytes: int(*chunk),
	}
	if err := validateAndFixOptions(&opt); err != nil {
		logger.Fatalf("invalid options: %v", err)
	}

	if err := encryptFileAtomic(*in, *out, pw, opt); err != nil {
		logger.Fatalf("encrypt failed: %v", err)
	}
	zero(pw)
	logger.Println("encryption successful")
}

func dec(args []string) {
	fs := flag.NewFlagSet("dec", flag.ExitOnError)
	in := fs.String("i", "", "input file")
	out := fs.String("o", "", "output file")
	overwrite := fs.Bool("overwrite", false, "overwrite output if exists")
	_ = fs.Parse(args)

	if *in == "" || *out == "" {
		fmt.Fprintln(os.Stderr, "missing -i or -o")
		os.Exit(2)
	}
	if !*overwrite && fileExists(*out) {
		ok, err := confirm(fmt.Sprintf("Overwrite %s? [y/N]: ", *out))
		if err != nil {
			logger.Printf("prompt failed: %v", err)
			os.Exit(1)
		}
		if !ok {
			os.Exit(1)
		}
	}
	pw, err := readPassword("Password: ")
	if err != nil {
		logger.Fatalf("read password: %v", err)
	}
	if len(pw) == 0 {
		logger.Fatal("empty password")
	}

	if err := decryptFileAtomic(*in, *out, pw); err != nil {
		logger.Fatalf("decrypt failed: %v", err)
	}
	zero(pw)
	logger.Println("decryption successful")
}

func pw(args []string) {
	fs := flag.NewFlagSet("pw", flag.ExitOnError)
	size := fs.Uint("s", 16, "password length")
	_ = fs.Parse(args)
	n := int(*size)
	if n <= 0 || n > 1024 {
		logger.Fatal("invalid size")
	}
	out, err := randomPassword(n)
	if err != nil {
		logger.Fatalf("generate password: %v", err)
	}
	fmt.Println(string(out))
	zero(out)
}

// validateAndFixOptions enforces conservative bounds on user-supplied parameters.
func validateAndFixOptions(opt *encryptOptions) error {
	if opt.Time == 0 {
		opt.Time = timeDef
	}
	if opt.Time > timeMax {
		return fmt.Errorf("time too large (>%d)", timeMax)
	}
	if opt.MemoryKB == 0 {
		opt.MemoryKB = memoryKBDef
	}
	if opt.MemoryKB > memoryKBMax {
		return fmt.Errorf("memory too large (>%d KB)", memoryKBMax)
	}
	maxThreads := runtime.NumCPU()
	if maxThreads < 1 {
		maxThreads = 1
	}
	threadsCap := maxThreads * 4
	if threadsCap > threadsMaxCap {
		threadsCap = threadsMaxCap
	}
	if opt.Threads == 0 {
		opt.Threads = uint8(maxThreads)
	}
	if int(opt.Threads) > threadsCap {
		return fmt.Errorf("threads too large (>%d)", threadsCap)
	}
	if opt.ChunkBytes <= 0 {
		opt.ChunkBytes = chunkDefault
	}
	if opt.ChunkBytes < chunkMin || opt.ChunkBytes > chunkMax {
		return fmt.Errorf("chunk size must be between %d and %d", chunkMin, chunkMax)
	}
	return nil
}

// encryptFileAtomic writes output to a temporary file in the destination directory and renames it on success.
// It writes header + HMAC followed by framed ciphertext chunks.
func encryptFileAtomic(inPath, outPath string, password []byte, opt encryptOptions) error {
	dir := filepath.Dir(outPath)
	tmp, err := os.CreateTemp(dir, tmpPrefix)
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmp.Name()

	// register temp path for signal cleanup
	select {
	case tempFilesToRemove <- tmpPath:
	default:
	}

	// ensure temp is removed on early return
	defer func() {
		_ = os.Remove(tmpPath)
	}()

	// set file mode (best-effort; not fatal)
	_ = tmp.Chmod(0o600)

	// do encryption writing to tmp
	if err := encryptToWriter(inPath, tmp, password, opt); err != nil {
		_ = tmp.Close()
		return err
	}

	// flush & close
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}

	// atomic rename
	if err := os.Rename(tmpPath, outPath); err != nil {
		return fmt.Errorf("rename temp file: %w", err)
	}
	return nil
}

// encryptToWriter performs the actual encryption and writes to the provided writer (usually a temp file).
func encryptToWriter(inPath string, out io.Writer, password []byte, opt encryptOptions) error {
	// generate salt and base nonce
	salt := make([]byte, saltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return fmt.Errorf("generate salt: %w", err)
	}
	baseNonce := make([]byte, baseNonceLen)
	if _, err := io.ReadFull(rand.Reader, baseNonce); err != nil {
		return fmt.Errorf("generate base nonce: %w", err)
	}

	// derive keys (AEAD key + HMAC key)
	derived := argon2.IDKey(password, salt, opt.Time, opt.MemoryKB, opt.Threads, uint32(derivedKeyLen))
	defer func() {
		zero(derived)
		runtime.KeepAlive(derived)
	}()
	aeadKey := derived[:keyLen]
	hmacKey := derived[keyLen:derivedKeyLen]

	h := header{
		Version:   formatVersion,
		Time:      opt.Time,
		MemoryKB:  opt.MemoryKB,
		Threads:   opt.Threads,
		SaltLen:   uint8(len(salt)),
		Reserved:  0,
		Salt:      salt,
		BaseNonce: baseNonce,
	}
	// write header and get AAD (exact bytes)
	aad, err := writeHeader(out, &h)
	if err != nil {
		return fmt.Errorf("write header: %w", err)
	}
	// compute HMAC over header bytes and write it
	hmacVal := computeHMAC(hmacKey, aad)
	if _, err := out.Write(hmacVal); err != nil {
		return fmt.Errorf("write header hmac: %w", err)
	}

	// create AEAD
	aead, err := chacha20poly1305.NewX(aeadKey)
	if err != nil {
		return fmt.Errorf("create aead: %w", err)
	}

	// open input file
	inFile, err := os.Open(inPath)
	if err != nil {
		return fmt.Errorf("open input: %w", err)
	}
	defer inFile.Close()

	buf := make([]byte, opt.ChunkBytes)
	counter := uint64(0)
	lenBuf := make([]byte, 4)

	for {
		n, rErr := io.ReadFull(inFile, buf)
		if rErr != nil && rErr != io.ErrUnexpectedEOF && rErr != io.EOF {
			return fmt.Errorf("read input: %w", rErr)
		}
		if n == 0 {
			break
		}
		pt := buf[:n]
		nonce := makeNonce(baseNonce, counter)
		ct := aead.Seal(nil, nonce, pt, aad)
		binary.LittleEndian.PutUint32(lenBuf, uint32(len(ct)))
		if _, err := out.Write(lenBuf); err != nil {
			return fmt.Errorf("write length: %w", err)
		}
		if _, err := out.Write(ct); err != nil {
			return fmt.Errorf("write ciphertext: %w", err)
		}
		counter++
		if rErr == io.ErrUnexpectedEOF || rErr == io.EOF {
			break
		}
	}
	return nil
}

// decryptFileAtomic decrypts to a temp file and renames the result on success.
func decryptFileAtomic(inPath, outPath string, password []byte) error {
	dir := filepath.Dir(outPath)
	tmp, err := os.CreateTemp(dir, tmpPrefix)
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmp.Name()
	select {
	case tempFilesToRemove <- tmpPath:
	default:
	}
	defer func() {
		_ = os.Remove(tmpPath)
	}()

	_ = tmp.Chmod(0o600)

	if err := decryptToWriter(inPath, tmp, password); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}
	if err := os.Rename(tmpPath, outPath); err != nil {
		return fmt.Errorf("rename temp file: %w", err)
	}
	return nil
}

// decryptToWriter performs header reading, HMAC verification, and chunk decryption to writer.
func decryptToWriter(inPath string, out io.Writer, password []byte) error {
	inFile, err := os.Open(inPath)
	if err != nil {
		return fmt.Errorf("open input: %w", err)
	}
	defer inFile.Close()

	// read header bytes and HMAC
	hdrBuf, hdr, err := readHeaderAndBuf(inFile)
	if err != nil {
		return fmt.Errorf("read header: %w", err)
	}

	// derive keys
	derived := argon2.IDKey(password, hdr.Salt, hdr.Time, hdr.MemoryKB, hdr.Threads, uint32(derivedKeyLen))
	defer func() {
		zero(derived)
		runtime.KeepAlive(derived)
	}()
	aeadKey := derived[:keyLen]
	hmacKey := derived[keyLen:derivedKeyLen]

	// verify HMAC (protects header integrity)
	hmacOnDisk := make([]byte, hmacSize)
	if _, err := io.ReadFull(inFile, hmacOnDisk); err != nil {
		return fmt.Errorf("read header hmac: %w", err)
	}
	expected := computeHMAC(hmacKey, hdrBuf)
	if !hmac.Equal(hmacOnDisk, expected) {
		return errors.New("header integrity check failed (wrong password or corrupted file)")
	}
	// AAD includes header bytes (same as written)
	aad := hdrBuf

	aead, err := chacha20poly1305.NewX(aeadKey)
	if err != nil {
		return fmt.Errorf("create aead: %w", err)
	}

	lenBuf := make([]byte, 4)
	counter := uint64(0)

	for {
		_, rErr := io.ReadFull(inFile, lenBuf)
		if rErr == io.EOF {
			break
		}
		if rErr != nil {
			return fmt.Errorf("read length: %w", rErr)
		}
		size := binary.LittleEndian.Uint32(lenBuf)
		if size > uint32(chunkMax)+chacha20poly1305.Overhead {
			return errors.New("invalid chunk size")
		}
		ct := make([]byte, int(size))
		if _, err := io.ReadFull(inFile, ct); err != nil {
			return fmt.Errorf("read ciphertext: %w", err)
		}
		nonce := makeNonce(hdr.BaseNonce, counter)
		pt, err := aead.Open(nil, nonce, ct, aad)
		if err != nil {
			return fmt.Errorf("decrypt chunk %d: %w", counter, err)
		}
		if _, err := out.Write(pt); err != nil {
			return fmt.Errorf("write plaintext: %w", err)
		}
		counter++
	}
	return nil
}

// writeHeader serializes header to writer and returns the header bytes used as AAD.
func writeHeader(w io.Writer, h *header) ([]byte, error) {
	total := 1 + len(magic) + 4 + 4 + 1 + 1 + 2 + len(h.Salt) + baseNonceLen
	buf := make([]byte, 0, total)
	buf = append(buf, byte(h.Version))
	buf = append(buf, []byte(magic)...)
	tmp4 := make([]byte, 4)
	binary.LittleEndian.PutUint32(tmp4, h.Time)
	buf = append(buf, tmp4...)
	binary.LittleEndian.PutUint32(tmp4, h.MemoryKB)
	buf = append(buf, tmp4...)
	buf = append(buf, h.Threads)
	buf = append(buf, h.SaltLen)
	buf = append(buf, 0, 0) // reserved
	buf = append(buf, h.Salt...)
	buf = append(buf, h.BaseNonce...)

	if _, err := w.Write(buf); err != nil {
		return nil, fmt.Errorf("write header: %w", err)
	}
	return buf, nil
}

// readHeaderAndBuf reads header fields from reader and returns the raw header bytes and parsed header.
func readHeaderAndBuf(r io.Reader) ([]byte, *header, error) {
	var h header
	// Read version + magic first to verify size
	verBuf := make([]byte, 1)
	if _, err := io.ReadFull(r, verBuf); err != nil {
		return nil, nil, fmt.Errorf("read version: %w", err)
	}
	h.Version = uint8(verBuf[0])
	if h.Version != formatVersion {
		return nil, nil, fmt.Errorf("unsupported file version: %d", h.Version)
	}
	magicBuf := make([]byte, len(magic))
	if _, err := io.ReadFull(r, magicBuf); err != nil {
		return nil, nil, fmt.Errorf("read magic: %w", err)
	}
	if string(magicBuf) != magic {
		return nil, nil, errors.New("magic mismatch (not a chachacrypt file)")
	}
	tmp4 := make([]byte, 4)
	if _, err := io.ReadFull(r, tmp4); err != nil {
		return nil, nil, fmt.Errorf("read time: %w", err)
	}
	h.Time = binary.LittleEndian.Uint32(tmp4)
	if _, err := io.ReadFull(r, tmp4); err != nil {
		return nil, nil, fmt.Errorf("read memory: %w", err)
	}
	h.MemoryKB = binary.LittleEndian.Uint32(tmp4)
	b1 := make([]byte, 1)
	if _, err := io.ReadFull(r, b1); err != nil {
		return nil, nil, fmt.Errorf("read threads: %w", err)
	}
	h.Threads = uint8(b1[0])
	if _, err := io.ReadFull(r, b1); err != nil {
		return nil, nil, fmt.Errorf("read saltlen: %w", err)
	}
	h.SaltLen = uint8(b1[0])
	res := make([]byte, 2)
	if _, err := io.ReadFull(r, res); err != nil {
		return nil, nil, fmt.Errorf("read reserved: %w", err)
	}
	h.Reserved = binary.LittleEndian.Uint16(res)
	h.Salt = make([]byte, int(h.SaltLen))
	if _, err := io.ReadFull(r, h.Salt); err != nil {
		return nil, nil, fmt.Errorf("read salt: %w", err)
	}
	h.BaseNonce = make([]byte, baseNonceLen)
	if _, err := io.ReadFull(r, h.BaseNonce); err != nil {
		return nil, nil, fmt.Errorf("read base nonce: %w", err)
	}

	// reconstruct header buffer exactly as written (version + magic + fields + salt + baseNonce)
	total := 1 + len(magic) + 4 + 4 + 1 + 1 + 2 + len(h.Salt) + baseNonceLen
	buf := make([]byte, total)
	off := 0
	buf[off] = byte(h.Version)
	off++
	copy(buf[off:off+len(magic)], []byte(magic))
	off += len(magic)
	binary.LittleEndian.PutUint32(buf[off:off+4], h.Time)
	off += 4
	binary.LittleEndian.PutUint32(buf[off:off+4], h.MemoryKB)
	off += 4
	buf[off] = byte(h.Threads)
	off++
	buf[off] = byte(h.SaltLen)
	off++
	binary.LittleEndian.PutUint16(buf[off:off+2], h.Reserved)
	off += 2
	copy(buf[off:off+len(h.Salt)], h.Salt)
	off += len(h.Salt)
	copy(buf[off:off+baseNonceLen], h.BaseNonce)

	return buf, &h, nil
}

// computeHMAC returns HMAC-SHA256 over message using key.
func computeHMAC(key, message []byte) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(message)
	return mac.Sum(nil)
}

// makeNonce constructs a 24-byte XChaCha nonce by copying base (16 bytes) and appending counter (8 bytes little-endian).
func makeNonce(base []byte, counter uint64) []byte {
	n := make([]byte, nonceSizeX)
	copy(n, base)
	binary.LittleEndian.PutUint64(n[baseNonceLen:], counter)
	return n
}

// readPassword reads password from tty without echo.
func readPassword(prompt string) ([]byte, error) {
	fmt.Fprint(os.Stderr, prompt)
	pw, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	return pw, err
}

// confirm prompts user and returns true if they answered 'y' or 'Y'.
func confirm(prompt string) (bool, error) {
	fmt.Fprint(os.Stderr, prompt)
	rd := bufio.NewReader(os.Stdin)
	line, err := rd.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return false, err
	}
	if len(line) > 0 && (line[0] == 'y' || line[0] == 'Y') {
		return true, nil
	}
	return false, nil
}

// randomPassword generates a password of length n.
func randomPassword(n int) ([]byte, error) {
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{};:,.?/"
	out := make([]byte, n)
	buf := make([]byte, 1)
	for i := 0; i < n; i++ {
		if _, err := io.ReadFull(rand.Reader, buf); err != nil {
			return nil, err
		}
		out[i] = alphabet[int(buf[0])%len(alphabet)]
	}
	return out, nil
}

// zero overwrites slice content (best-effort) and calls KeepAlive.
func zero(b []byte) {
	if b == nil {
		return
	}
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}

// fileExists checks if path exists and is a regular file (not a directory).
func fileExists(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return !info.IsDir()
}
