package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"io"
)

func TestAuthHandler(t *testing.T) {
	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(AuthHandler))
	defer server.Close()

	// Test with valid private key (POST request)
	resp, err := http.Post(server.URL, "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status code %d, but got %d", http.StatusOK, resp.StatusCode)
	}

	// Test with expired private key (POST request)
	expiredURL := server.URL + "?expired=true"
	resp, err = http.Post(expiredURL, "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status code %d, but got %d", http.StatusOK, resp.StatusCode)
	}
}

func TestJWKSHandler(t *testing.T) {
	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(JWKSHandler))
	defer server.Close()

	// Test JWKS request
	resp, err := http.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status code %d, but got %d", http.StatusOK, resp.StatusCode)
	}

	// Check the response content
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	expected := `{"keys":[{"kid":"aRandomKeyID","alg":"RS256","kty":"RSA","use":"sig","n":"`
	if !strings.Contains(string(body), expected) {
		t.Errorf("Response body does not contain the expected content.")
	}
}
