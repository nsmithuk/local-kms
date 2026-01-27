package integration

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/nsmithuk/local-kms/src"
	"github.com/nsmithuk/local-kms/src/config"
	"github.com/nsmithuk/local-kms/src/data"
)

func setupTestServer(t *testing.T) (*httptest.Server, func()) {
	tempDir, err := os.MkdirTemp("", "local-kms-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}

	config.DatabasePath = filepath.Join(tempDir, "data")
	config.AWSAccountId = "111122223333"
	config.AWSRegion = "us-east-1"

	database := data.NewDatabase(config.DatabasePath)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		src.HandleRequest(w, r, database)
	}))

	// Return cleanup function
	cleanup := func() {
		database.Close()
		server.Close()
		os.RemoveAll(tempDir)
	}

	return server, cleanup
}

func makeKMSRequest(t *testing.T, server *httptest.Server, operation string, payload interface{}) (*http.Response, map[string]interface{}) {
	var body []byte
	var err error
	if payload != nil {
		body, err = json.Marshal(payload)
		if err != nil {
			t.Fatalf("Failed to marshal payload: %v", err)
		}
	} else {
		body = []byte("{}")
	}

	req, err := http.NewRequest("POST", server.URL, bytes.NewBuffer(body))
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	req.Header.Set("X-Amz-Target", fmt.Sprintf("TrentService.%s", operation))

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Failed to make request: %v", err)
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response: %v", err)
	}
	defer resp.Body.Close()

	var responseData map[string]interface{}
	if len(respBody) > 0 {
		if err := json.Unmarshal(respBody, &responseData); err != nil {
			// If JSON parsing fails, store raw response
			responseData = map[string]interface{}{
				"raw_response": string(respBody),
			}
		}
	}

	return resp, responseData
}

func TestDescribeKey_NonExistentKey(t *testing.T) {
	server, cleanup := setupTestServer(t)
	defer cleanup()

	// Test with non-existent key ID
	keyId := "arn:aws:kms:us-east-1:111122223333:key/00000000-1111-2222-3333-444444444444"
	resp, data := makeKMSRequest(t, server, "DescribeKey", map[string]interface{}{
		"KeyId": keyId,
	})

	if resp.StatusCode != 400 {
		t.Errorf("Expected status code 400, got %d", resp.StatusCode)
	}

	if errorType, exists := data["__type"]; exists {
		if errorType != "NotFoundException" {
			t.Errorf("Expected error type 'NotFoundException', got '%v'", errorType)
		}
	} else {
		t.Error("Expected error response to contain '__type' field")
	}

	expectedMsg := fmt.Sprintf("Key '%s' does not exist", keyId)
	if errorMsg, exists := data["message"]; exists {
		if errorMsg.(string) != expectedMsg {
			t.Errorf("Expected error '%v', got '%v'", expectedMsg, errorMsg)
		}
	} else {
		t.Error("Expected error response to contain '__type' field")
	}
}

func TestDescribeKey_ExistingKey(t *testing.T) {
	server, cleanup := setupTestServer(t)
	defer cleanup()

	// First create a key
	createResp, createData := makeKMSRequest(t, server, "CreateKey", nil)
	if createResp.StatusCode != 200 {
		t.Fatalf("Failed to create key: status %d, data: %+v", createResp.StatusCode, createData)
	}

	keyMetadata, exists := createData["KeyMetadata"].(map[string]interface{})
	if !exists {
		t.Fatalf("Create response missing KeyMetadata: %+v", createData)
	}

	keyId, exists := keyMetadata["KeyId"].(string)
	if !exists {
		t.Fatalf("KeyMetadata missing KeyId: %+v", keyMetadata)
	}

	keyArn, exists := keyMetadata["Arn"].(string)
	if !exists {
		t.Fatalf("KeyMetadata missing Arn: %+v", keyMetadata)
	}

	describeResp, describeData := makeKMSRequest(t, server, "DescribeKey", map[string]interface{}{
		"KeyId": keyId,
	})

	if describeResp.StatusCode != 200 {
		t.Errorf("Expected status code 200, got %d. Response: %+v", describeResp.StatusCode, describeData)
	}

	describedMetadata, exists := describeData["KeyMetadata"].(map[string]interface{})
	if !exists {
		t.Fatalf("Describe response missing KeyMetadata: %+v", describeData)
	}

	if describedKeyId := describedMetadata["KeyId"]; describedKeyId != keyId {
		t.Errorf("Expected KeyId '%s', got '%v'", keyId, describedKeyId)
	}

	if describedArn := describedMetadata["Arn"]; describedArn != keyArn {
		t.Errorf("Expected Arn '%s', got '%v'", keyArn, describedArn)
	}

	if keyUsage := describedMetadata["KeyUsage"]; keyUsage != "ENCRYPT_DECRYPT" {
		t.Errorf("Expected KeyUsage 'ENCRYPT_DECRYPT', got '%v'", keyUsage)
	}

	if keyState := describedMetadata["KeyState"]; keyState != "Enabled" {
		t.Errorf("Expected KeyState 'Enabled', got '%v'", keyState)
	}
}

func TestDescribeKey_ByArn(t *testing.T) {
	server, cleanup := setupTestServer(t)
	defer cleanup()

	createResp, createData := makeKMSRequest(t, server, "CreateKey", nil)
	if createResp.StatusCode != 200 {
		t.Fatalf("Failed to create key: status %d", createResp.StatusCode)
	}

	keyMetadata := createData["KeyMetadata"].(map[string]interface{})
	keyArn := keyMetadata["Arn"].(string)

	describeResp, describeData := makeKMSRequest(t, server, "DescribeKey", map[string]interface{}{
		"KeyId": keyArn,
	})

	if describeResp.StatusCode != 200 {
		t.Errorf("Expected status code 200, got %d", describeResp.StatusCode)
	}

	describedMetadata := describeData["KeyMetadata"].(map[string]interface{})
	if describedArn := describedMetadata["Arn"]; describedArn != keyArn {
		t.Errorf("Expected Arn '%s', got '%v'", keyArn, describedArn)
	}
}

func TestDescribeKey_WithAlias(t *testing.T) {
	server, cleanup := setupTestServer(t)
	defer cleanup()

	// Create a key
	createResp, createData := makeKMSRequest(t, server, "CreateKey", nil)
	if createResp.StatusCode != 200 {
		t.Fatalf("Failed to create key: status %d", createResp.StatusCode)
	}

	keyMetadata := createData["KeyMetadata"].(map[string]interface{})
	keyId := keyMetadata["KeyId"].(string)

	// Create an alias
	aliasName := "alias/test-key"
	aliasResp, _ := makeKMSRequest(t, server, "CreateAlias", map[string]interface{}{
		"AliasName":   aliasName,
		"TargetKeyId": keyId,
	})
	if aliasResp.StatusCode != 200 {
		t.Fatalf("Failed to create alias: status %d", aliasResp.StatusCode)
	}

	// Describe using alias
	describeResp, describeData := makeKMSRequest(t, server, "DescribeKey", map[string]interface{}{
		"KeyId": aliasName,
	})

	if describeResp.StatusCode != 200 {
		t.Errorf("Expected status code 200, got %d", describeResp.StatusCode)
	}

	describedMetadata := describeData["KeyMetadata"].(map[string]interface{})
	if describedKeyId := describedMetadata["KeyId"]; describedKeyId != keyId {
		t.Errorf("Expected KeyId '%s', got '%v'", keyId, describedKeyId)
	}
}
