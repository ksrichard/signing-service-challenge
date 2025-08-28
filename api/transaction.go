package api

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
)

type SignTxRequest struct {
	DeviceID string `json:"deviceId"`
	Data     string `json:"data"`
}

func (r *SignTxRequest) Validate() error {
	if strings.ReplaceAll(r.DeviceID, " ", "") == "" {
		return errors.New("deviceId is required")
	}

	if strings.ReplaceAll(r.Data, " ", "") == "" {
		return errors.New("data is required")
	}

	return nil
}

type SignTxResponse struct {
	Signature  string `json:"signature"`
	SignedData string `json:"signed_data"`
}

func (s *Server) SignTransaction(response http.ResponseWriter, request *http.Request) {
	// parse and validate request JSON
	requestJSON, ok := parseRequestJSON[SignTxRequest](response, request)
	if !ok {
		return
	}
	if err := requestJSON.Validate(); err != nil {
		WriteErrorResponse(response, http.StatusBadRequest, []string{
			fmt.Sprintf("Request validation failed: %s", err.Error()),
		})
		return
	}

	// find device
	device, err := s.deviceStore.Get(requestJSON.DeviceID)
	if err != nil {
		WriteErrorResponse(response, http.StatusNotFound, []string{
			fmt.Sprintf("Unable to find signature device: %s", err.Error()),
		})
		return
	}

	// sign data
	result, err := device.SignData(requestJSON.Data)
	if err != nil {
		WriteErrorResponse(response, http.StatusInternalServerError, []string{
			fmt.Sprintf("Failed to sign data: %s", err.Error()),
		})
		return
	}

	WriteAPIResponse(response, http.StatusOK, SignTxResponse{
		Signature:  result.Signature,
		SignedData: result.SignedData,
	})
}
