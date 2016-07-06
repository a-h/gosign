package gosign

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
)

// Handler is the http.Handler implementation for the Signature Handler.
type Handler struct {
	next http.Handler
	priv *rsa.PrivateKey
}

// NewHandler creates a HTTP handler which executes the "next" handler,
// intercepting the body and adding both a SHA256 checksum and a signature
// to the HTTP header collection.
//
// The new headers are called "X-Sha256hash" and "X-Signature" respectively.
func NewHandler(priv *rsa.PrivateKey, next http.Handler) *Handler {
	return &Handler{
		priv: priv,
		next: next,
	}
}

func (h Handler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	// Record the response.
	// Based on https://justinas.org/writing-http-middleware-in-go/
	rec := httptest.NewRecorder()
	h.next.ServeHTTP(rec, req)

	// Copy the response from the recording, with the modifications.
	for k, v := range rec.Header() {
		w.Header()[k] = v
	}

	// Add the SHA256 hash of the response body.
	hash := sha256.Sum256([]byte(rec.Body.Bytes()))
	w.Header().Set("X-Sha256hash", base64.StdEncoding.EncodeToString(hash[:]))

	// Sign the response.
	// The input is signed directly for compatibility with openssl command lines.
	signature, err := rsa.SignPKCS1v15(rand.Reader, h.priv, 0, hash[:])

	if err != nil {
		log.Print("Unable to sign the HTTP body, with error", err)
	}

	w.Header().Set("X-Signature", base64.StdEncoding.EncodeToString(signature))

	// Then the status code, as this call writes out the headers
	w.WriteHeader(rec.Code)

	// Write out the original body.
	w.Write(rec.Body.Bytes())
}

// LoadPrivateKeyFromFile loads an RSA private key in PEM format from disk.
func LoadPrivateKeyFromFile(filename string) (*rsa.PrivateKey, error) {
	pemBytes, err := ioutil.ReadFile(filename)

	block, _ := pem.Decode(pemBytes)
	pri, err := x509.ParsePKCS1PrivateKey(block.Bytes)

	return pri, err
}

// LoadPublicKeyFromFile loads an RSA public key in PEM format from disk.
func LoadPublicKeyFromFile(filename string) (*rsa.PublicKey, error) {
	pemBytes, err := ioutil.ReadFile(filename)

	block, _ := pem.Decode(pemBytes)
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)

	return pub.(*rsa.PublicKey), err
}

// Verify the hash. hashed is created by hashing the input message. The sig
// parameter is the signature of the hash to verify.
func Verify(pub *rsa.PublicKey, hashed []byte, sig []byte) error {
	return rsa.VerifyPKCS1v15(pub, 0, hashed, sig)
}
