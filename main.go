package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"strconv"
	"time"

	"database/sql"

	"github.com/golang-jwt/jwt/v5"
	_ "github.com/mattn/go-sqlite3"
)

const databaseFileName = "totally_not_my_privateKeys.db"

// Structure for database connection
var db *sql.DB

type Database interface {
	Query(query string, args ...interface{}) (*sql.Rows, error)
	// Other database operations you need in your code
}

func main() {
	// Open the SQLite database file
	var err error
	db, err = sql.Open("sqlite3", databaseFileName)
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	// Create the keys table if it doesn't exist
	createTableSQL := `
	CREATE TABLE IF NOT EXISTS keys(
		kid TEXT PRIMARY KEY,
		key BLOB NOT NULL,
		exp INTEGER NOT NULL
	);
	`
	_, err = db.Exec(createTableSQL)
	if err != nil {
		log.Fatalf("Failed to create table: %v", err)
	}

	genKeys()
	http.HandleFunc("/.well-known/jwks.json", JWKSHandler)
	http.HandleFunc("/auth", AuthHandler)
	log.Fatal(http.ListenAndServe(":8080", nil))
}

var (
	goodPrivKey    *rsa.PrivateKey
	expiredPrivKey *rsa.PrivateKey
)

func genKeys() {
	// generate global key pair
	var err error
	goodPrivKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Error generating RSA keys: %v", err)
	}

	// Generate an expired key pair for demonstration purposes
	expiredPrivKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Error generating expired RSA keys: %v", err)
	}

	// Store the keys in the database
	storeKey(goodKID, goodPrivKey, time.Now().Add(1*time.Hour).Unix())
	storeKey("expiredKeyId", expiredPrivKey, time.Now().Add(-1*time.Hour).Unix())
}

const goodKID = "aRandomKeyID"

func storeKey(kid string, key *rsa.PrivateKey, exp int64) {
	// Serialize the private key to a string
	keyBytes := encodePrivateKeyToPEM(key)

	// Insert the key into the database
	insertSQL := "INSERT OR REPLACE INTO keys(kid, key, exp) VALUES (?, ?, ?)"
	_, err := db.Exec(insertSQL, kid, keyBytes, exp)
	if err != nil {
		log.Fatalf("Failed to insert key into the database: %v", err)
	}
}

func encodePrivateKeyToPEM(key *rsa.PrivateKey) []byte {
	// Serialize the private key to PKCS1 PEM format
	keyBytes := x509.MarshalPKCS1PrivateKey(key)
	return keyBytes
}

func AuthHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var (
		signingKey *rsa.PrivateKey
		keyID      string
		exp        int64
	)

	// Default to the good key
	signingKey = goodPrivKey
	keyID = goodKID
	exp = time.Now().Add(1 * time.Hour).Unix()

	// If the expired query parameter is set, use the expired key
	if expired, _ := strconv.ParseBool(r.URL.Query().Get("expired")); expired {
		signingKey = expiredPrivKey
		keyID = "expiredKeyId"
		exp = time.Now().Add(-1 * time.Hour).Unix()
	}

	// Create the token with the expiry
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"exp": exp,
	})
	// Set the key ID header
	token.Header["kid"] = keyID
	// Sign the token with the private key
	signedToken, err := token.SignedString(signingKey)
	if err != nil {
		http.Error(w, "failed to sign token", http.StatusInternalServerError)
		return
	}

	_, _ = w.Write([]byte(signedToken))
}

type (
	JWKS struct {
		Keys []JWK `json:"keys"`
	}
	JWK struct {
		KID       string `json:"kid"`
		Algorithm string `json:"alg"`
		KeyType   string `json:"kty"`
		Use       string `json:"use"`
		N         string `json:"n"`
		E         string `json:"e"`
	}
)

func JWKSHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	// Retrieve all valid (non-expired) keys from the database
	keys, err := retrieveValidKeys()
	if err != nil {
		http.Error(w, "failed to retrieve valid keys", http.StatusInternalServerError)
		return
	}

	// Create a JWKS response from the retrieved keys
	resp := JWKS{
		Keys: make([]JWK, len(keys)),
	}
	for i, key := range keys {
		resp.Keys[i] = JWK{
			KID:       key.kid,
			Algorithm: "RS256",
			KeyType:   "RSA",
			Use:       "sig",
			N:         base64URLEncode(key.key.PublicKey.N),
			E:         base64URLEncode(big.NewInt(int64(key.key.PublicKey.E))),
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func base64URLEncode(b *big.Int) string {
	return base64.RawURLEncoding.EncodeToString(b.Bytes())
}

type keyInfo struct {
	kid string
	key *rsa.PrivateKey
	exp int64
}

func retrieveValidKeys() ([]keyInfo, error) {
	// Retrieve all keys from the database
	query := "SELECT kid, key, exp FROM keys"
	rows, err := db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var keys []keyInfo
	for rows.Next() {
		var kid string
		var keyBytes []byte
		var exp int64

		err := rows.Scan(&kid, &keyBytes, &exp)
		if err != nil {
			return nil, err
		}

		// Deserialize the private key from the stored bytes
		key, err := decodePrivateKeyFromPEM(keyBytes)
		if err != nil {
			return nil, err
		}

		// Check if the key is still valid (not expired)
		if time.Unix(exp, 0).After(time.Now()) {
			keys = append(keys, keyInfo{kid: kid, key: key, exp: exp})
		}
	}
	return keys, nil
}

func decodePrivateKeyFromPEM(pemBytes []byte) (*rsa.PrivateKey, error) {
	// Parse the PEM data and return an RSA private key
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return key, nil
}
