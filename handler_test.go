package gosign

import (
	"crypto/sha256"
	"encoding/base64"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestThatTheHandlerExecutesTheHandlerThatItWraps(t *testing.T) {
	// Arrange.
	testBody, err := ioutil.ReadFile("testdata/data.json")

	if err != nil {
		t.Fatal("Failed to read test data", err)
	}

	h := &TestHandler{
		body: testBody,
	}

	pk, err := LoadPrivateKeyFromFile("testdata/private_test.pem")

	if err != nil {
		t.Fatal("Failed to load private key.")
	}

	// Create the handler.
	signer := NewHandler(pk, h)

	// Create a mock request to capture the result.
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "http://example.com/foo", nil)

	// Act.
	signer.ServeHTTP(w, req)

	// Assert.
	actualbody := string(w.Body.Bytes())
	expectedbody := string(testBody)

	// Check that the wrapped handler executed properly.
	if !h.wasExecuted {
		t.Error("Expected the wrapped handler, but it was not executed.")
	}

	if actualbody != expectedbody {
		t.Errorf("Expected the wrapped handler to affect the HTTP output, but the body was not the expected value. The actual body response was \"%s\", the expected was \"%s\"", actualbody, expectedbody)
	}

	if w.Header().Get("x-test") != "x-test-value" {
		t.Error("Expected HTTP headers set by the wrapped handler to be retained, but they were lost.")
	}

	// Check the hash and signature headers are correct, and match with the openssl command line tools.
	expectedHashBytes, _ := ioutil.ReadFile("testdata/hash.b64")
	expectedHash := strings.TrimSpace(string(expectedHashBytes))
	actualHash := w.Header().Get("X-Sha256hash")

	if actualHash != expectedHash {
		t.Errorf("Expected the hash to be \"%s\", but it was \"%s\"", expectedHash, actualHash)
	}

	expectedSignatureBytes, _ := ioutil.ReadFile("testdata/signature.b64")
	expectedSignature := strings.Replace(strings.TrimSpace(string(expectedSignatureBytes)), "\n", "", -1)
	actualSignature := w.Header().Get("X-Signature")

	if actualSignature != expectedSignature {
		t.Errorf("Expected the signature to be \"%s\", but was \"%s\"", expectedSignature, actualSignature)
	}

	// Validate the signature independently of the service.
	// This is what a service which wants to validate the response from a signed service would do.
	// For example, if the server response was persisted to a database and we needed to prove that
	// the database contents hadn't been modified. This would be done by comparing the indpendently
	// calculated hash to the result of decrypting the signature with the public key and checking
	// that they're the same.
	pub, _ := LoadPublicKeyFromFile("testdata/public_test.pem")
	independentBodyHash := sha256.Sum256(testBody)
	serviceProvidedSignature, err := base64.StdEncoding.DecodeString(actualSignature)

	if err != nil {
		t.Error("Failed to base64 decode the signature returned by the service.")
	}

	err = Verify(pub, independentBodyHash[:], serviceProvidedSignature)

	if err != nil {
		t.Error("Failed to independently verify the signature with error: ", err)
	}
}

type TestHandler struct {
	body        []byte
	wasExecuted bool
}

func (th *TestHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	w.Write(th.body)
	th.wasExecuted = true
	w.Header().Add("x-test", "x-test-value")
}
