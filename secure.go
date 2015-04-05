package secure

import (
	"crypto/rand"
	"errors"
	"io"

	"golang.org/x/crypto/nacl/box"
)

// Size (in bytes) of the nonce for NaCl box seal/open
const NonceSize = 24

// Size (in bytes) of the key for NaCl box seal/open
const KeySize = 32

// Size (in bytes) of total additional overhead added by encryption
const TotalOverhead = NonceSize + box.Overhead

// Size (in bytes) of the max message size supported by this package
const MaxMessageSize = 32 * 1024

func newNonce() ([NonceSize]byte, error) {
	var nonce [NonceSize]byte
	n, err := rand.Read(nonce[:])

	if err != nil {
		return nonce, err
	}

	if n != NonceSize {
		return nonce, errors.New("not enough bytes read for nonce")
	}

	return nonce, nil
}

type Reader struct {
	r         io.Reader
	priv, pub *[KeySize]byte
}

// Read decrypts a stream encrypted with box.Seal.
// It expects the nonce used to be prepended
// to the ciphertext
func (s Reader) Read(p []byte) (int, error) {
	// make a buffer large enough to handle
	// the overhead associated with an encrypted message
	// (the tag and nonce)
	enc := make([]byte, (len(p) + TotalOverhead))
	n, err := s.r.Read(enc)

	if err != nil {
		return n, err
	}

	// strip off the nonce
	// and any extra space at the end of the buffer
	nonceSlice := enc[:NonceSize]
	enc = enc[NonceSize:n]

	// convert the slice to an array
	// for use in box.Open
	var nonce [NonceSize]byte
	copy(nonce[:], nonceSlice)

	decrypt, auth := box.Open(nil, enc, &nonce, s.pub, s.priv)
	// if authentication failed, output bottom
	if !auth {
		return 0, errors.New("decrypt error")
	}

	if len(decrypt) > len(p) {
		return 0, errors.New("decrypt error")
	}

	n = copy(p, decrypt)

	return n, nil
}

type Writer struct {
	w         io.Writer
	priv, pub *[KeySize]byte
}

// ReadFrom reads from a reader (assumed to be a SecureReader)
// and writes to the SecureWriter.
// This implementation is almost identical to the default
// implementation in io.Copy, but it takes into account
// that the written (encrypted) message is expected to be larger than
// the read (plaintext) message.
func (s Writer) ReadFrom(r io.Reader) (int64, error) {
	buf := make([]byte, (MaxMessageSize + TotalOverhead))

	var n int64
	var err error

	for {
		nr, er := r.Read(buf)
		if nr > 0 {
			nw, ew := s.Write(buf[:nr])
			if nw > 0 {
				n += int64(nw)
			}
			if ew != nil {
				err = ew
				break
			}
			if (nr + TotalOverhead) != nw {
				err = io.ErrShortWrite
				break
			}
		}
		if er == io.EOF {
			break
		}
		if er != nil {
			err = er
			break
		}
	}
	return n, err
}

// Write encrypts a plaintext stream using box.Seal
func (s Writer) Write(p []byte) (int, error) {
	nonce, err := newNonce()

	if err != nil {
		return 0, err
	}

	enc := box.Seal(nil, p, &nonce, s.pub, s.priv)
	// tack the nonce onto the encrypted message
	encWithNonce := append(nonce[:], enc...)

	n, err := s.w.Write(encWithNonce)

	// return an error if the complete message wasn't written
	// this case also fulfills the contract that Write must return
	// an error if n < len(p) since len(encWithNonce) is guaranteed
	// to be greater than len(p)
	if n < len(encWithNonce) {
		return n, errors.New("failed to write complete encrypted message")
	}

	return n, err
}

// NewReader instantiates a new secure Reader
// priv and pub should be keys generated with box.GenerateKey
func NewReader(r io.Reader, priv, pub *[KeySize]byte) io.Reader {
	return Reader{r, priv, pub}
}

// NewWriter instantiates a new secure Writer
// priv and pub should be keys generated with box.GenerateKey
func NewWriter(w io.Writer, priv, pub *[KeySize]byte) io.Writer {
	return Writer{w, priv, pub}
}