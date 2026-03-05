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

type TimeUnit string

const (
	TimeUnitSeconds TimeUnit = "seconds"
	TimeUnitMinutes TimeUnit = "minutes"
	TimeUnitHours   TimeUnit = "hours"
	TimeUnitDays    TimeUnit = "days"
	TimeUnitWeeks   TimeUnit = "weeks"
	TimeUnitMonths  TimeUnit = "months"
)
type ExpiresInDuration struct {
	Duration int    `json:"duration" yaml:"duration"`
	Unit     TimeUnit `json:"unit" yaml:"unit"`
}

// APIKeyCreatedEvent represents the payload for "apikey.created" event type.
// This event is sent when an external API key is registered to hybrid gateways.
type APIKeyCreatedEvent struct {
	// ApiId identifies the API this key belongs to
	ApiId string `json:"apiId"`

	// Name is the unique name of the API key
	Name string `json:"name,omitempty"`

	// ApiKeyHashes contains the hashed API key values (keyed by algorithm name)
	// Example: {"sha256": "abc123...", "sha512": "def456..."}
	// Hashing is done in platform-api before sending to gateways
	ApiKeyHashes map[string]string `json:"apiKeyHashes"`

	// Masked api key to display
	MaskedApiKey string `json:"maskedApiKey"`

	// ExternalRefId is an optional reference ID for tracing purposes
	ExternalRefId *string `json:"externalRefId,omitempty"`

	// ExpiresAt is the optional expiration time in ISO 8601 format
	ExpiresAt *string `json:"expiresAt,omitempty"`

	// ExpiresIn is the optional expiration duration
	ExpiresIn *ExpiresInDuration `json:"expiresIn,omitempty"`
}

// APIKeyRevokedEvent represents the payload for "apikey.revoked" event type.
// This event is sent when an API key is revoked from hybrid gateways.
type APIKeyRevokedEvent struct {
	// ApiId identifies the API this key belongs to
	ApiId string `json:"apiId"`

	// KeyName is the unique name of the API key that was revoked
	KeyName string `json:"keyName"`
}

// APIKeyUpdatedEvent represents the payload for "apikey.updated" event type.
// This event is sent when an API key is updated/regenerated on hybrid gateways.
type APIKeyUpdatedEvent struct {
	// ApiId identifies the API this key belongs to
	ApiId string `json:"apiId"`

	// KeyName is the unique name of the API key being updated
	KeyName string `json:"keyName"`

	// ExternalRefId is an optional reference ID for tracing purposes
	ExternalRefId *string `json:"externalRefId,omitempty"`

	// ExpiresIn is the optional expiration duration
	ExpiresIn *ExpiresInDuration `json:"expiresIn,omitempty"`

	// ApiKeyHashes contains the hashed API key values (keyed by algorithm name)
	// Example: {"sha256": "abc123...", "sha512": "def456..."}
	// Hashing is done in platform-api before sending to gateways
	ApiKeyHashes map[string]string `json:"apiKeyHashes"`

	// ExpiresAt is the optional new expiration time in ISO 8601 format
	ExpiresAt *string `json:"expiresAt,omitempty"`
}

// APIKeysBatchSyncEvent represents the payload for "apikeys.sync" event type.
// This event is sent when multiple API keys need to be synced to a gateway in a single batch.
// Typically used when deploying an API to a new gateway for the first time.
type APIKeysBatchSyncEvent struct {
	// ApiId identifies the API these keys belong to
	ApiId string `json:"apiId"`

	// ApiKeys is the array of API keys to sync
	ApiKeys []APIKeyCreatedEvent `json:"apiKeys"`
}
