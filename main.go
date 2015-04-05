package main

import (
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"

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

type secureReader struct {
	r         io.Reader
	priv, pub *[KeySize]byte
}

// Read decrypts a stream encrypted with box.Seal.
// It expects the nonce used to be prepended
// to the ciphertext
func (s secureReader) Read(p []byte) (int, error) {
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

type secureWriter struct {
	w         io.Writer
	priv, pub *[KeySize]byte
}

// ReadFrom reads from a reader (assumed to be a SecureReader)
// and writes to the SecureWriter.
// This implementation is almost identical to the default
// implementation in io.Copy, but it takes into account
// that the written (encrypted) message is expected to be larger than
// the read (plaintext) message.
func (s secureWriter) ReadFrom(r io.Reader) (int64, error) {
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
func (s secureWriter) Write(p []byte) (int, error) {
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

// NewSecureReader instantiates a new SecureReader
func NewSecureReader(r io.Reader, priv, pub *[KeySize]byte) io.Reader {
	return secureReader{r, priv, pub}
}

// NewSecureWriter instantiates a new SecureWriter
func NewSecureWriter(w io.Writer, priv, pub *[KeySize]byte) io.Writer {
	return secureWriter{w, priv, pub}
}

type secureConn struct {
	io.Reader
	io.Writer
	io.Closer
}

// Dial generates a private/public key pair,
// connects to the server, perform the handshake
// and return a reader/writer.
func Dial(addr string) (io.ReadWriteCloser, error) {
	pub, priv, err := box.GenerateKey(rand.Reader)

	if err != nil {
		return nil, err
	}

	conn, err := net.Dial("tcp", addr)

	if err != nil {
		return nil, err
	}

	// first thing we do is send our public key
	_, err = conn.Write(pub[:])

	if err != nil {
		return nil, err
	}

	// wait for the server's public key
	peerPubSlice := make([]byte, KeySize)
	n, err := conn.Read(peerPubSlice)

	if err != nil {
		return nil, err
	}

	peerPubSlice = peerPubSlice[:n]
	var peerPub [KeySize]byte
	copy(peerPub[:], peerPubSlice)

	secCon := secureConn{
		NewSecureReader(conn, priv, &peerPub),
		NewSecureWriter(conn, priv, &peerPub),
		conn,
	}

	return secCon, nil
}

// Serve starts a secure echo server on the given listener.
func Serve(l net.Listener) error {
	pub, priv, err := box.GenerateKey(rand.Reader)

	if err != nil {
		return err
	}

	for {
		conn, err := l.Accept()
		if err != nil {
			return err
		}

		go handleConnection(conn, pub, priv)
	}
}

func handleConnection(c net.Conn, pub, priv *[32]byte) {
	defer c.Close()
	// first wait for the client's public key
	peerPubSlice := make([]byte, KeySize)
	n, err := c.Read(peerPubSlice)

	if err != nil {
		log.Println(err)
	}

	peerPubSlice = peerPubSlice[:n]
	var peerPub [KeySize]byte
	copy(peerPub[:], peerPubSlice)

	// then, send our public key
	_, err = c.Write(pub[:])

	if err != nil {
		log.Println(err)
	}

	// now session is "secure"
	sr := NewSecureReader(c, priv, &peerPub)
	sw := NewSecureWriter(c, priv, &peerPub)

	// echo
	_, err = io.Copy(sw, sr)

	if err != nil {
		log.Println(err)
	}
}

func main() {
	port := flag.Int("l", 0, "Listen mode. Specify port")
	flag.Parse()

	// Server mode
	if *port != 0 {
		l, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
		if err != nil {
			log.Fatal(err)
		}
		defer l.Close()
		log.Fatal(Serve(l))
	}

	// Client mode
	if len(os.Args) != 3 {
		log.Fatalf("Usage: %s <port> <message>", os.Args[0])
	}
	conn, err := Dial("localhost:" + os.Args[1])
	if err != nil {
		log.Fatal(err)
	}
	if _, err := conn.Write([]byte(os.Args[2])); err != nil {
		log.Fatal(err)
	}
	buf := make([]byte, len(os.Args[2]))
	n, err := conn.Read(buf)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s\n", buf[:n])
}
