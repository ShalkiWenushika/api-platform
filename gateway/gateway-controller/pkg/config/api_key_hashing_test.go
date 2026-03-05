/*
 * Copyright (c) 2025, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package config

import (
	"testing"
)

func TestValidateAPIKeyConfig(t *testing.T) {
	tests := []struct {
		name                 string
		apiKeysPerUserPerAPI int
		expectError          bool
	}{
		{
			name:                 "zero api keys per user per api",
			apiKeysPerUserPerAPI: 0,
			expectError:          true,
		},
		{
			name:                 "negative api keys per user per api",
			apiKeysPerUserPerAPI: -1,
			expectError:          true,
		},
		{
			name:                 "valid api keys per user per api",
			apiKeysPerUserPerAPI: 10,
			expectError:          false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &Config{
				APIKey: APIKeyConfig{
					APIKeysPerUserPerAPI: tt.apiKeysPerUserPerAPI,
				},
			}

			err := config.validateAPIKeyConfig()

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error but got: %v", err)
				}
			}
		})
	}
}
