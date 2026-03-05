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

package model

import (
	"time"
)

// APIKey represents an API key for artifact authentication
type APIKey struct {
	ID           string            `json:"id" db:"id"`
	ArtifactUUID string            `json:"artifactUuid" db:"artifact_uuid"`
	Name         string            `json:"name" db:"name"`
	MaskedAPIKey string            `json:"maskedApiKey" db:"masked_api_key"`
	APIKeyHashes map[string]string `json:"apiKeyHashes" db:"api_key_hashes"`
	Status       string            `json:"status" db:"status"` // active, revoked, expired
	CreatedAt    time.Time         `json:"createdAt" db:"created_at"`
	CreatedBy    string            `json:"createdBy" db:"created_by"`
	UpdatedAt    time.Time         `json:"updatedAt" db:"updated_at"`
	ExpiresAt    *time.Time        `json:"expiresAt,omitempty" db:"expires_at"` // Pointer for NULL support
}

// TableName returns the table name for the APIKey model
func (APIKey) TableName() string {
	return "api_keys"
}

// IsActive returns true if API key status is active
func (k *APIKey) IsActive() bool {
	return k.Status == "active"
}

// IsExpired returns true if the API key has expired
func (k *APIKey) IsExpired() bool {
	if k.ExpiresAt == nil {
		return false
	}
	return time.Now().After(*k.ExpiresAt)
}

// Revoke marks the API key as revoked with current timestamp
func (k *APIKey) Revoke() {
	k.Status = "revoked"
	k.UpdatedAt = time.Now()
}
