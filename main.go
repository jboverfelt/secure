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

const NonceSize = 24
const KeySize = 32

func newNonce() ([NonceSize]byte, error) {
	var nonce [NonceSize]byte
	n, err := rand.Read(nonce[:])

	if err != nil {
		return nonce, err
	}

	if n != NonceSize {
		return nonce, errors.New("Not enough bytes read for nonce")
	}

	return nonce, nil
}

type secureReader struct {
	wrappedReader io.Reader
	priv, pub     *[KeySize]byte
}

// decrypt
func (r secureReader) Read(p []byte) (int, error) {
	encryptedMessage := make([]byte, len(p))
	n, err := r.wrappedReader.Read(encryptedMessage)

	if err != nil {
		return n, err
	}

	if len(encryptedMessage) < (NonceSize + box.Overhead + 1) {
		return n, errors.New("SecureReader: Read: buffer for Read not large enough to accomodate nonce and message")
	}

	// strip off the nonce
	// and any extra space at the end of the buffer
	nonceSlice := encryptedMessage[:NonceSize]
	encryptedMessage = encryptedMessage[NonceSize:n]

	// convert the slice to an array
	var nonce [NonceSize]byte
	copy(nonce[:], nonceSlice)

	decryptedMessage, auth := box.Open(nil, encryptedMessage, &nonce, r.pub, r.priv)
	// if authentication failed, output bottom
	if !auth {
		return 0, errors.New("Decrypt error")
	}

	if len(decryptedMessage) > len(p) {
		return 0, errors.New("Decrypt error")
	}

	bytesWritten := copy(p, decryptedMessage)

	return bytesWritten, nil
}

type secureWriter struct {
	wrappedWriter io.Writer
	priv, pub     *[KeySize]byte
}

// encrypt
func (w secureWriter) Write(p []byte) (int, error) {
	nonce, err := newNonce()

	if err != nil {
		return 0, err
	}

	encryptedMessage := box.Seal(nil, p, &nonce, w.pub, w.priv)
	// tack the nonce onto the encrypted message
	encWithNonce := append(nonce[:], encryptedMessage...)

	n, err := w.wrappedWriter.Write(encWithNonce)

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
	return nil
}

func handleConnection(c net.Conn, pub, priv *[32]byte) error {
	defer c.Close()
	// first wait for the client's public key
	peerPubSlice := make([]byte, KeySize)
	n, err := c.Read(peerPubSlice)

	if err != nil {
		return err
	}

	peerPubSlice = peerPubSlice[:n]
	var peerPub [KeySize]byte
	copy(peerPub[:], peerPubSlice)

	// then, send our public key
	_, err = c.Write(pub[:])

	if err != nil {
		return err
	}

	// now session is "secure"
	secureReader := NewSecureReader(c, priv, &peerPub)
	secureWriter := NewSecureWriter(c, priv, &peerPub)

	// echo
	_, err = io.Copy(secureWriter, secureReader)

	return err
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
	buf := make([]byte, 2048)
	n, err := conn.Read(buf)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s\n", buf[:n])
}
