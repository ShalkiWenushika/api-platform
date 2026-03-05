/*
 *  Copyright (c) 2026, WSO2 LLC. (http://www.wso2.org) All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package utils

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"strings"
)

const (
	apiKeyLen = 32 // Length in bytes (32 bytes = 64 hex characters)
)

// Supported hashing algorithms for API keys
var supportedHashAlgorithms = map[string]bool{
	"sha256": true,
	// Future algorithms can be added here
	// "sha512": true,
	// "bcrypt": true,
}

// GenerateAPIKey generates a cryptographically secure API key
// Format: {64_hex_chars} (32 random bytes hex-encoded)
func GenerateAPIKey() (string, error) {
	randomBytes := make([]byte, apiKeyLen)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}
	return hex.EncodeToString(randomBytes), nil
}

// HashAPIKey hashes an API key using the specified algorithms
// Returns a map of algorithm name to hex-encoded hash
// Invalid/unsupported algorithms are logged and ignored
// Example: {"sha256": "abc123...", "sha512": "def456..."}
func HashAPIKey(plainKey string, algorithms []string) (map[string]string, error) {
	if plainKey == "" {
		return nil, fmt.Errorf("API key cannot be empty")
	}

	if len(algorithms) == 0 {
		return nil, fmt.Errorf("at least one hashing algorithm must be specified")
	}

	hashes := make(map[string]string)

	// Process only valid algorithms, log and skip invalid ones
	for _, algorithm := range algorithms {
		normalizedAlgo := strings.ToLower(algorithm)

		// Skip unsupported algorithms with logging
		if !supportedHashAlgorithms[normalizedAlgo] {
			log.Printf("Warning: Unsupported hashing algorithm '%s' provided, ignoring it. Supported algorithms: sha256", algorithm)
			continue
		}

		switch normalizedAlgo {
		case "sha256":
			hash, err := HashWithSHA256(plainKey)
			if err != nil {
				return nil, fmt.Errorf("failed to hash with SHA256: %w", err)
			}
			hashes["sha256"] = hash
		}
	}

	// If no valid algorithms were found after filtering, return error
	if len(hashes) == 0 {
		return nil, fmt.Errorf("no valid hashing algorithms found in the provided list")
	}

	return hashes, nil
}

// HashWithSHA256 hashes an API key using SHA-256
// Returns the hex-encoded hash (64 characters)
// No salt is used - this is deterministic by design for lookup
func HashWithSHA256(plainKey string) (string, error) {
	// Normalize the API key by trimming whitespace
	trimmedKey := strings.TrimSpace(plainKey)
	if trimmedKey == "" {
		return "", fmt.Errorf("API key cannot be empty")
	}

	// Generate hash using SHA-256 (no salt - deterministic)
	hasher := sha256.New()
	hasher.Write([]byte(trimmedKey))
	hash := hasher.Sum(nil)

	// Return hex-encoded hash (64 characters)
	return hex.EncodeToString(hash), nil
}

// MaskAPIKey masks an API key for secure logging and display
// Shows last 5 characters prefixed with 3 stars (e.g. "***ab123")
func MaskAPIKey(apiKey string) string {
	if len(apiKey) < 5 {
		return "********"
	}
	return "***" + apiKey[len(apiKey)-5:]
}
