package secure

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/nacl/box"
)

// Size (in bytes) of the nonce for NaCl box seal/open
const NonceSize = 24

// Size (in bytes) of the key for NaCl box seal/open
const KeySize = 32

// Size (in bytes) of the max message size supported by this package
const MaxMessageSize = 32 * 1024

// ErrNonceSize means that the source of randomness did not provide
// enough bytes for a complete nonce
var ErrNonceSize = errors.New("not enough bytes read for nonce")

// ErrDecrypt means that there was a problem during decryption
var ErrDecrypt = errors.New("decrypt error")

// ErrEncWrite means that a complete encrypted message was unable to be written
var ErrEncWrite = errors.New("failed to write complete encrypted message")

// A Reader is an io.Reader that can be used to read streams
// of encrypted data that was encrypted using the Writer from this package.
// The Reader will decrypt and return the plaintext from
// the provided io.Reader.
type Reader struct {
	r         io.Reader
	priv, pub *[KeySize]byte
	shared    [KeySize]byte
}

// Read decrypts a stream encrypted with box.Seal.
// It expects the nonce used to be prepended
// to the ciphertext
func (s Reader) Read(p []byte) (int, error) {
	// Read the nonce from the stream
	var nonce [NonceSize]byte
	if n, err := io.ReadFull(s.r, nonce[:]); err != nil {
		fmt.Println(err)
		fmt.Println(n)
		return 0, errors.New("nonce")
	}

	// Read the ciphertext size
	var size uint16
	if err := binary.Read(s.r, binary.LittleEndian, &size); err != nil {
		return 0, errors.New("size")
	}

	// Ensure buffer is large enough for ciphertext
	if uint16(len(p)) < size-box.Overhead {
		return 0, errors.New("wrong size")
	}

	// make a buffer large enough to handle
	// the overhead associated with an encrypted message
	enc := make([]byte, size)
	if _, err := io.ReadFull(s.r, enc); err != nil {
		return 0, errors.New("msg")
	}

	decrypt, auth := box.OpenAfterPrecomputation(p[0:0], enc, &nonce, &s.shared)
	// if authentication failed, output bottom
	if !auth {
		return 0, ErrDecrypt
	}

	return len(decrypt), nil
}

// A Writer is an io.Writer which will encrypt the provided data
// and write it to the provided wrapped io.Writer
type Writer struct {
	w         io.Writer
	priv, pub *[KeySize]byte
	shared    [KeySize]byte
}

// Write encrypts a plaintext stream using box.Seal
func (s Writer) Write(p []byte) (int, error) {
	var nonce [24]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return 0, errors.New("secureWriter: cant generate random nonce: " + err.Error())
	}

	// write nonce
	_, err := s.w.Write(nonce[:])
	if err != nil {
		return 0, ErrEncWrite
	}

	enc := box.SealAfterPrecomputation(nil, p, &nonce, &s.shared)

	// write ciphertext length
	if err := binary.Write(s.w, binary.LittleEndian, uint16(len(enc))); err != nil {
		return 0, ErrEncWrite
	}

	// write ciphertext
	if _, err = s.w.Write(enc); err != nil {
		return 0, ErrEncWrite
	}

	return len(p), err
}

// NewReader instantiates a new secure Reader
// priv and pub should be keys generated with box.GenerateKey
func NewReader(r io.Reader, priv, pub *[KeySize]byte) io.Reader {
	sr := Reader{r: r, priv: priv, pub: pub}
	box.Precompute(&sr.shared, pub, priv)
	return sr
}

// NewWriter instantiates a new secure Writer
// priv and pub should be keys generated with box.GenerateKey
func NewWriter(w io.Writer, priv, pub *[KeySize]byte) io.Writer {
	sw := Writer{w: w, priv: priv, pub: pub}
	box.Precompute(&sw.shared, pub, priv)
	return sw
}
