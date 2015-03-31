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

func newNonce() ([24]byte, error) {
	var nonce [24]byte
	_, err := rand.Read(nonce[:])

	if err != nil {
		return nonce, err
	}

	return nonce, nil
}

type secureReader struct {
	wrappedReader io.Reader
	priv, pub     *[32]byte
}

// decrypt
func (r secureReader) Read(p []byte) (int, error) {
	encryptedMessage := make([]byte, len(p))
	n, err := r.wrappedReader.Read(encryptedMessage)

	if err != nil {
		return n, err
	}

	// strip off the nonce
	// and any extra space at the end of the buffer
	nonceSlice := encryptedMessage[:24]
	encryptedMessage = encryptedMessage[24:n]

	// convert the slice to an array
	var nonce [24]byte
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
	priv, pub     *[32]byte
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
func NewSecureReader(r io.Reader, priv, pub *[32]byte) io.Reader {
	return secureReader{r, priv, pub}
}

// NewSecureWriter instantiates a new SecureWriter
func NewSecureWriter(w io.Writer, priv, pub *[32]byte) io.Writer {
	return secureWriter{w, priv, pub}
}

// Dial generates a private/public key pair,
// connects to the server, perform the handshake
// and return a reader/writer.
func Dial(addr string) (io.ReadWriteCloser, error) {
	return nil, nil
}

// Serve starts a secure echo server on the given listener.
func Serve(l net.Listener) error {
	return nil
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
