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

package repository

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"platform-api/src/internal/database"
	"platform-api/src/internal/model"
)

// APIKeyRepo implements APIKeyRepository
type APIKeyRepo struct {
	db *database.DB
}

// NewAPIKeyRepo creates a new API key repository
func NewAPIKeyRepo(db *database.DB) APIKeyRepository {
	return &APIKeyRepo{db: db}
}

// CreateAPIKey inserts a new API key into the database
func (r *APIKeyRepo) CreateAPIKey(apiKey *model.APIKey) error {
	tx, err := r.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Set timestamps
	apiKey.CreatedAt = time.Now()
	apiKey.UpdatedAt = time.Now()

	// Serialize api_key_hashes to JSON
	var hashesJSON string
	if len(apiKey.APIKeyHashes) > 0 {
		jsonBytes, err := json.Marshal(apiKey.APIKeyHashes)
		if err != nil {
			return fmt.Errorf("failed to marshal api_key_hashes: %w", err)
		}
		hashesJSON = string(jsonBytes)
	} else {
		hashesJSON = "{}"
	}

	query := `
		INSERT INTO api_keys (id, artifact_uuid, name, masked_api_key, api_key_hashes,
		                      status, created_at, created_by, updated_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`
	_, err = tx.Exec(r.db.Rebind(query),
		apiKey.ID,
		apiKey.ArtifactUUID,
		apiKey.Name,
		apiKey.MaskedAPIKey,
		hashesJSON,
		apiKey.Status,
		apiKey.CreatedAt,
		apiKey.CreatedBy,
		apiKey.UpdatedAt,
		apiKey.ExpiresAt,
	)
	if err != nil {
		return fmt.Errorf("failed to insert API key: %w", err)
	}

	return tx.Commit()
}

// GetAPIKeyByID retrieves an API key by ID and artifact UUID
func (r *APIKeyRepo) GetAPIKeyByID(id, artifactUUID string) (*model.APIKey, error) {
	apiKey := &model.APIKey{}
	var hashesJSON string

	query := `
		SELECT id, artifact_uuid, name, masked_api_key, api_key_hashes,
		       status, created_at, created_by, updated_at, expires_at
		FROM api_keys
		WHERE id = ? AND artifact_uuid = ?
	`

	err := r.db.QueryRow(r.db.Rebind(query), id, artifactUUID).Scan(
		&apiKey.ID,
		&apiKey.ArtifactUUID,
		&apiKey.Name,
		&apiKey.MaskedAPIKey,
		&hashesJSON,
		&apiKey.Status,
		&apiKey.CreatedAt,
		&apiKey.CreatedBy,
		&apiKey.UpdatedAt,
		&apiKey.ExpiresAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get API key by ID: %w", err)
	}

	// Deserialize api_key_hashes from JSON
	if hashesJSON != "" && hashesJSON != "{}" {
		if err := json.Unmarshal([]byte(hashesJSON), &apiKey.APIKeyHashes); err != nil {
			return nil, fmt.Errorf("failed to unmarshal api_key_hashes: %w", err)
		}
	}

	return apiKey, nil
}

// GetAPIKeyByName retrieves an API key by name and artifact UUID
func (r *APIKeyRepo) GetAPIKeyByName(artifactUUID, name string) (*model.APIKey, error) {
	apiKey := &model.APIKey{}
	var hashesJSON string

	query := `
		SELECT id, artifact_uuid, name, masked_api_key, api_key_hashes,
		       status, created_at, created_by, updated_at, expires_at
		FROM api_keys
		WHERE artifact_uuid = ? AND name = ?
	`

	err := r.db.QueryRow(r.db.Rebind(query), artifactUUID, name).Scan(
		&apiKey.ID,
		&apiKey.ArtifactUUID,
		&apiKey.Name,
		&apiKey.MaskedAPIKey,
		&hashesJSON,
		&apiKey.Status,
		&apiKey.CreatedAt,
		&apiKey.CreatedBy,
		&apiKey.UpdatedAt,
		&apiKey.ExpiresAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get API key by name: %w", err)
	}

	// Deserialize api_key_hashes from JSON
	if hashesJSON != "" && hashesJSON != "{}" {
		if err := json.Unmarshal([]byte(hashesJSON), &apiKey.APIKeyHashes); err != nil {
			return nil, fmt.Errorf("failed to unmarshal api_key_hashes: %w", err)
		}
	}

	return apiKey, nil
}

// GetAPIKeysByArtifact retrieves all API keys for an artifact
func (r *APIKeyRepo) GetAPIKeysByArtifact(artifactUUID string) ([]*model.APIKey, error) {
	query := `
		SELECT id, artifact_uuid, name, masked_api_key, api_key_hashes,
		       status, created_at, created_by, updated_at, expires_at
		FROM api_keys
		WHERE artifact_uuid = ?
		ORDER BY created_at DESC
	`

	rows, err := r.db.Query(r.db.Rebind(query), artifactUUID)
	if err != nil {
		return nil, fmt.Errorf("failed to query API keys: %w", err)
	}
	defer rows.Close()

	var apiKeys []*model.APIKey
	for rows.Next() {
		apiKey := &model.APIKey{}
		var hashesJSON string

		err := rows.Scan(
			&apiKey.ID,
			&apiKey.ArtifactUUID,
			&apiKey.Name,
			&apiKey.MaskedAPIKey,
			&hashesJSON,
			&apiKey.Status,
			&apiKey.CreatedAt,
			&apiKey.CreatedBy,
			&apiKey.UpdatedAt,
			&apiKey.ExpiresAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan API key: %w", err)
		}

		// Deserialize api_key_hashes from JSON
		if hashesJSON != "" && hashesJSON != "{}" {
			if err := json.Unmarshal([]byte(hashesJSON), &apiKey.APIKeyHashes); err != nil {
				return nil, fmt.Errorf("failed to unmarshal api_key_hashes: %w", err)
			}
		}

		apiKeys = append(apiKeys, apiKey)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating API keys: %w", err)
	}

	return apiKeys, nil
}

// UpdateAPIKey updates an existing API key
func (r *APIKeyRepo) UpdateAPIKey(apiKey *model.APIKey) error {
	tx, err := r.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Update timestamp
	apiKey.UpdatedAt = time.Now()

	// Serialize api_key_hashes to JSON
	var hashesJSON string
	if len(apiKey.APIKeyHashes) > 0 {
		jsonBytes, err := json.Marshal(apiKey.APIKeyHashes)
		if err != nil {
			return fmt.Errorf("failed to marshal api_key_hashes: %w", err)
		}
		hashesJSON = string(jsonBytes)
	} else {
		hashesJSON = "{}"
	}

	query := `
		UPDATE api_keys
		SET masked_api_key = ?,
		    api_key_hashes = ?,
		    status = ?,
		    updated_at = ?,
		    expires_at = ?
		WHERE id = ? AND artifact_uuid = ?
	`

	_, err = tx.Exec(r.db.Rebind(query),
		apiKey.MaskedAPIKey,
		hashesJSON,
		apiKey.Status,
		apiKey.UpdatedAt,
		apiKey.ExpiresAt,
		apiKey.ID,
		apiKey.ArtifactUUID,
	)
	if err != nil {
		return fmt.Errorf("failed to update API key: %w", err)
	}

	return tx.Commit()
}

// DeleteAPIKey deletes an API key (hard delete)
func (r *APIKeyRepo) DeleteAPIKey(id, artifactUUID string) error {
	query := `DELETE FROM api_keys WHERE id = ? AND artifact_uuid = ?`
	_, err := r.db.Exec(r.db.Rebind(query), id, artifactUUID)
	if err != nil {
		return fmt.Errorf("failed to delete API key: %w", err)
	}
	return nil
}
