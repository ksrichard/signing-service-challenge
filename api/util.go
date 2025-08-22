package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// allowedMethods checks if the request method is one of the allowed methods.
// If returns false, the response will be written with an error, so handler can return immediately
func allowedMethods(response http.ResponseWriter, request *http.Request, methods ...string) bool {
	for _, method := range methods {
		if request.Method != method {
			WriteErrorResponse(response, http.StatusMethodNotAllowed, []string{
				http.StatusText(http.StatusMethodNotAllowed),
			})
			return false
		}
	}

	return true
}

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
