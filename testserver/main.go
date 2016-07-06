package main

import (
	"net/http"

	"github.com/a-h/gosign"
	"github.com/gorilla/mux"
)

func main() {
	// Initialise the Gorilla Router.
	r := mux.NewRouter()

	// Create a test Hello World handler.
	helloHandler := &helloHandler{}

	// Load the private key, and create an instance of the signing
	// middleware which wraps the helloHandler.
	priv, _ := gosign.LoadPrivateKeyFromFile("private.pem")
	helloSigner := gosign.NewHandler(priv, helloHandler)

	// Handle incoming HTTP requests.
	r.Handle("/", helloSigner)

	// Start the server with the routes.
	http.ListenAndServe(":8080", r)
}

type helloHandler struct {
}

func (th *helloHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("<h1>Hello!</h1>"))
	w.Write([]byte("<p>Check the HTTP headers to see the base64 encoded hash and signature.</p>"))
	w.Write([]byte("<p>Validate the signature with the public.pem key.</p>"))
}
