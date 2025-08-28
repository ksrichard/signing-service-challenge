package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// parseRequestJSON parses the request body as JSON and returns it.
// If the second return value is false, the handler must return because there was an error.
func parseRequestJSON[T any](response http.ResponseWriter, request *http.Request) (*T, bool) {
	body := request.Body
	defer body.Close()
	requestJSONRaw, err := io.ReadAll(body)
	if err != nil {
		WriteErrorResponse(response, http.StatusBadRequest, []string{
			"Unable to read request body",
		})
		return nil, false
	}
	var requestJSON T
	err = json.Unmarshal(requestJSONRaw, &requestJSON)
	if err != nil {
		WriteErrorResponse(response, http.StatusBadRequest, []string{
			fmt.Sprintf("Unable to parse request body: %s", err.Error()),
		})
		return nil, false
	}

	return &requestJSON, true
}
