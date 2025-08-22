package api

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/ksrichard/signing-service-challenge/crypto"
	"github.com/ksrichard/signing-service-challenge/domain"
)

type CreateSignatureDeviceRequest struct {
	Algorithm crypto.SignatureAlgorithm `json:"algorithm"`
	Label     string                    `json:"label"`
}

// Validate checks if the JSON request is valid.
func (r *CreateSignatureDeviceRequest) Validate() error {
	// validate algorithm
	switch r.Algorithm {
	case crypto.RSA, crypto.ECC:
		return nil
	}

	return errors.New("invalid algorithm")
}

// CreateSignatureDeviceResponse is the response when creating a signature device.
type CreateSignatureDeviceResponse struct {
	ID string `json:"id"`
}

// SignatureDeviceRouter handles requests to the signature device endpoint.
// It includes the CreateSignatureDevice and ListSignatureDevices methods.
func (s *Server) SignatureDeviceRouter(response http.ResponseWriter, request *http.Request) {
	switch request.Method {
	case http.MethodPost:
		s.CreateSignatureDevice(response, request)
	case http.MethodGet:
		s.ListSignatureDevices(response, request)
	default:
		WriteErrorResponse(response, http.StatusMethodNotAllowed, []string{
			http.StatusText(http.StatusMethodNotAllowed),
		})
	}
}

// CreateSignatureDevice creates a new signature device.
func (s *Server) CreateSignatureDevice(response http.ResponseWriter, request *http.Request) {
	// check allowed methods
	if ok := allowedMethods(response, request, http.MethodPost); !ok {
		return
	}

	// parse and validate request JSON
	requestJSON, ok := parseRequestJSON[CreateSignatureDeviceRequest](response, request)
	if !ok {
		return
	}
	if err := requestJSON.Validate(); err != nil {
		WriteErrorResponse(response, http.StatusBadRequest, []string{
			fmt.Sprintf("Request validation failed: %s", err.Error()),
		})
		return
	}

	// create new signature device
	device, err := domain.NewSignatureDevice(s.keyGeneratorStore, s.signerStore, requestJSON.Algorithm, requestJSON.Label)
	if err != nil {
		WriteErrorResponse(response, http.StatusBadRequest, []string{
			"Unable to create signature device",
		})
		return
	}

	err = s.deviceStore.Add(device)
	if err != nil {
		WriteErrorResponse(response, http.StatusBadRequest, []string{
			"Unable to save signature device",
		})
		return
	}

	log.Printf("New signature device (%s) saved: %q\n", requestJSON.Algorithm, device.GetIDStr())

	WriteAPIResponse(response, http.StatusOK, CreateSignatureDeviceResponse{
		ID: device.GetIDStr(),
	})
}

// signatureDevice is a representation of a signature device but as an API response.
type signatureDevice struct {
	ID               string                    `json:"id"`
	Algorithm        crypto.SignatureAlgorithm `json:"algorithm"`
	PublicKey        []byte                    `json:"publicKey"`
	Label            string                    `json:"label"`
	SignatureCounter uint64                    `json:"signatureCounter"`
}

// ListSignatureDevices lists all signature devices.
func (s *Server) ListSignatureDevices(response http.ResponseWriter, request *http.Request) {
	// check allowed methods
	if ok := allowedMethods(response, request, http.MethodGet); !ok {
		return
	}

	// list devices
	devices, err := s.deviceStore.List()
	if err != nil {
		WriteErrorResponse(response, http.StatusBadRequest, []string{
			fmt.Sprintf("Unable to list signature devices: %s", err.Error()),
		})
		return
	}

	// convert to API response
	result := make([]signatureDevice, len(devices))
	for i, device := range devices {
		result[i] = signatureDevice{
			ID:               device.GetIDStr(),
			Algorithm:        device.Algorithm,
			PublicKey:        device.PublicKey,
			Label:            device.Label,
			SignatureCounter: device.GetSignatureCounter(),
		}
	}

	WriteAPIResponse(response, http.StatusOK, result)
}

// GetSignatureDevice returns a single signature device.
func (s *Server) GetSignatureDevice(response http.ResponseWriter, request *http.Request) {
	// check allowed methods
	if ok := allowedMethods(response, request, http.MethodGet); !ok {
		return
	}

	// get device id from path
	// this is a quick hack that would be much nicer with Go version 1.22+ using path parameters
	id := strings.TrimPrefix(request.URL.Path, "/api/v0/signature-device/")
	if strings.ReplaceAll(id, " ", "") == "" {
		WriteErrorResponse(response, http.StatusBadRequest, []string{
			"id is required",
		})
		return
	}

	device, err := s.deviceStore.Get(id)
	if err != nil {
		WriteErrorResponse(response, http.StatusNotFound, []string{
			fmt.Sprintf("Could not retrieve signature device: %s", err.Error()),
		})
		return
	}

	WriteAPIResponse(response, http.StatusOK, signatureDevice{
		ID:               device.GetIDStr(),
		Algorithm:        device.Algorithm,
		PublicKey:        device.PublicKey,
		Label:            device.Label,
		SignatureCounter: device.GetSignatureCounter(),
	})
}
