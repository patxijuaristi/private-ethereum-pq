package testingapi

import (
	"bytes"
	"encoding/json"
	"net/http"
)

func MakeAPICall(hash []byte, functionName string) {
	// Define the URL of the API endpoint
	url := "http://host.docker.internal:8080/test"

	// Define the request body
	requestBody, err := json.Marshal(map[string]interface{}{
		"hash":         hash,
		"functionName": functionName,
	})
	if err != nil {
		print(err)
		print("Error marshaling request body")
	}

	// Send a POST request to the API endpoint with the request body
	response, err := http.Post(url, "application/json", bytes.NewBuffer(requestBody))
	if err != nil {
		print(err)
		print("Error")
	}
	defer response.Body.Close()
}
