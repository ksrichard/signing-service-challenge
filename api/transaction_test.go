package api

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ksrichard/signing-service-challenge/crypto"
	"github.com/ksrichard/signing-service-challenge/domain"
	"github.com/ksrichard/signing-service-challenge/persistence"
)

// failingSigner implements crypto.Signer and always returns an error
type failingSigner struct{}

func (f failingSigner) Sign(dataToBeSigned []byte) ([]byte, error) { return nil, assertErr("signfail") }

// helper to perform raw JSON/body requests (not auto-marshaled)
func doRawReq(t *testing.T, handler http.HandlerFunc, method, target string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req := httptest.NewRequest(method, target, rdr)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	return rr
}

func TestSignTransaction_InvalidJSON(t *testing.T) {
	srv := newTestServer(t)
	// invalid JSON body
	rr := doRawReq(t, srv.SignTransaction, http.MethodPost, "/api/v0/sign-tx", []byte("{"))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestSignTransaction_ValidationError(t *testing.T) {
	srv := newTestServer(t)
	// missing deviceId
	body := map[string]any{"deviceId": " ", "data": "hello"}
	rr := doJSONReq(t, srv.SignTransaction, http.MethodPost, "/api/v0/sign-tx", nil, body)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
	var erresp ErrorResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &erresp)
	if len(erresp.Errors) == 0 || !strings.Contains(erresp.Errors[0], "Request validation failed") {
		t.Fatalf("unexpected error response: %+v", erresp)
	}
}

func TestSignTransaction_DeviceNotFound(t *testing.T) {
	srv := newTestServer(t)
	body := SignTxRequest{DeviceID: "does-not-exist", Data: "payload"}
	rr := doJSONReq(t, srv.SignTransaction, http.MethodPost, "/api/v0/sign-tx", nil, body)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rr.Code)
	}
}

func TestSignTransaction_SignDataFailure(t *testing.T) {
	// Build a server with a signer store that returns a failing signer
	kg := crypto.NewKeyGeneratorStore(map[crypto.SignatureAlgorithm]crypto.KeyGenerator{
		crypto.RSA: &crypto.RSAGenerator{},
	})
	ss := crypto.NewSignerStore(map[crypto.SignatureAlgorithm]crypto.SignerCreateFunc{
		crypto.RSA: func(privateKey []byte) (crypto.Signer, error) { return failingSigner{}, nil },
	})
	store := persistence.NewInMemorySignatureDeviceStore()
	srv := NewServer(ServerParams{KeyGeneratorStore: kg, SignerStore: ss, DeviceStore: store})

	dev, err := domain.NewSignatureDevice(srv.keyGeneratorStore, srv.signerStore, crypto.RSA, "lbl")
	if err != nil {
		t.Fatalf("create device: %v", err)
	}
	if err := srv.deviceStore.Add(dev); err != nil {
		t.Fatalf("add: %v", err)
	}

	body := SignTxRequest{DeviceID: dev.GetIDStr(), Data: "payload"}
	rr := doJSONReq(t, srv.SignTransaction, http.MethodPost, "/api/v0/sign-tx", nil, body)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d: %s", rr.Code, rr.Body.String())
	}
	var erresp ErrorResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &erresp)
	if len(erresp.Errors) == 0 || !strings.Contains(erresp.Errors[0], "Failed to sign data") {
		t.Fatalf("unexpected error response: %+v", erresp)
	}
}

func TestSignTransaction_Success(t *testing.T) {
	srv := newTestServer(t)
	// create and add a device
	dev, err := domain.NewSignatureDevice(srv.keyGeneratorStore, srv.signerStore, crypto.RSA, "lbl")
	if err != nil {
		t.Fatalf("create device: %v", err)
	}
	if err := srv.deviceStore.Add(dev); err != nil {
		t.Fatalf("add: %v", err)
	}

	body := SignTxRequest{DeviceID: dev.GetIDStr(), Data: "hello-world"}
	rr := doJSONReq(t, srv.SignTransaction, http.MethodPost, "/api/v0/sign-tx", nil, body)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var resp Response
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	// decode Data into SignTxResponse
	b, _ := json.Marshal(resp.Data)
	var txResp SignTxResponse
	if err := json.Unmarshal(b, &txResp); err != nil {
		t.Fatalf("remarshal: %v", err)
	}
	if txResp.Signature == "" || txResp.SignedData == "" {
		t.Fatalf("missing fields in response: %+v", txResp)
	}
}
