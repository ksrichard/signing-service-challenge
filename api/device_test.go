package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ksrichard/signing-service-challenge/crypto"
	"github.com/ksrichard/signing-service-challenge/domain"
	"github.com/ksrichard/signing-service-challenge/persistence"
)

type failingGenerator struct{}

func (f *failingGenerator) GenerateKeyPair() ([]byte, []byte, error) {
	return nil, nil, assertErr("genfail")
}

type assertErr string

func (e assertErr) Error() string { return string(e) }

type failingStore struct {
	persistence.InMemorySignatureDeviceStore
}

func (f *failingStore) Add(device *domain.SignatureDevice) error { return assertErr("addfail") }

// helper to create a test Server with configurable stores
func newTestServer(t *testing.T) *Server {
	t.Helper()
	kg := crypto.NewKeyGeneratorStore(map[crypto.SignatureAlgorithm]crypto.KeyGenerator{
		crypto.RSA: &crypto.RSAGenerator{},
		crypto.ECC: &crypto.ECCGenerator{},
	})
	ss := crypto.NewSignerStore(map[crypto.SignatureAlgorithm]crypto.SignerCreateFunc{
		crypto.RSA: func(privateKey []byte) (crypto.Signer, error) { return crypto.NewRSASigner(privateKey) },
		crypto.ECC: func(privateKey []byte) (crypto.Signer, error) { return crypto.NewECCSigner(privateKey) },
	})
	store := persistence.NewInMemorySignatureDeviceStore()
	return NewServer(ServerParams{
		ListenAddress:     "",
		SignerStore:       ss,
		KeyGeneratorStore: kg,
		DeviceStore:       store,
	})
}

func doJSONReq(t *testing.T, handler http.HandlerFunc, method, target string, url *string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		rdr = bytes.NewReader(b)
	}
	var reqUrl string
	if url != nil {
		reqUrl = *url
	} else {
		reqUrl = target
	}
	req := httptest.NewRequest(method, reqUrl, rdr)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	mux := http.NewServeMux()
	mux.Handle(fmt.Sprintf("%s %s", method, target), handler)
	mux.ServeHTTP(rr, req)
	return rr
}

func TestCreateSignatureDevice_Success_RSA(t *testing.T) {
	srv := newTestServer(t)
	body := CreateSignatureDeviceRequest{Algorithm: crypto.RSA, Label: "device-rsa"}
	rr := doJSONReq(t, srv.CreateSignatureDevice, http.MethodPost, "/api/v0/signature-device", nil, body)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var resp Response
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	m := resp.Data.(map[string]any) // Data is generic; decode again to map
	id, _ := m["id"].(string)
	if id == "" || strings.Contains(id, "-") || len(id) != 32 {
		t.Fatalf("unexpected id: %q", id)
	}
}

func TestCreateSignatureDevice_Success_ECC(t *testing.T) {
	srv := newTestServer(t)
	body := CreateSignatureDeviceRequest{Algorithm: crypto.ECC, Label: "device-ecc"}
	rr := doJSONReq(t, srv.CreateSignatureDevice, http.MethodPost, "/api/v0/signature-device", nil, body)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestCreateSignatureDevice_ValidateError_InvalidAlgorithm(t *testing.T) {
	srv := newTestServer(t)
	body := map[string]any{"algorithm": "OTHER", "label": "x"}
	rr := doJSONReq(t, srv.CreateSignatureDevice, http.MethodPost, "/api/v0/signature-device", nil, body)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
	var erresp ErrorResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &erresp); err != nil {
		t.Fatalf("unmarshal err: %v", err)
	}
	if len(erresp.Errors) == 0 || !strings.Contains(erresp.Errors[0], "Request validation failed") {
		t.Fatalf("unexpected error response: %+v", erresp)
	}
}

func TestCreateSignatureDevice_KeyGenFailure(t *testing.T) {
	// set RSA generator to failing one
	kg := crypto.NewKeyGeneratorStore(map[crypto.SignatureAlgorithm]crypto.KeyGenerator{
		crypto.RSA: &failingGenerator{},
	})
	ss := crypto.NewSignerStore(map[crypto.SignatureAlgorithm]crypto.SignerCreateFunc{
		crypto.RSA: func(privateKey []byte) (crypto.Signer, error) { return crypto.NewRSASigner(privateKey) },
	})
	store := persistence.NewInMemorySignatureDeviceStore()
	srv := NewServer(ServerParams{
		KeyGeneratorStore: kg,
		SignerStore:       ss,
		DeviceStore:       store,
	})
	body := CreateSignatureDeviceRequest{Algorithm: crypto.RSA, Label: "x"}
	rr := doJSONReq(t, srv.CreateSignatureDevice, http.MethodPost, "/api/v0/signature-device", nil, body)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
}

func TestCreateSignatureDevice_DeviceStoreAddFailure(t *testing.T) {
	kg := crypto.NewKeyGeneratorStore(map[crypto.SignatureAlgorithm]crypto.KeyGenerator{
		crypto.RSA: &crypto.RSAGenerator{},
	})
	ss := crypto.NewSignerStore(map[crypto.SignatureAlgorithm]crypto.SignerCreateFunc{
		crypto.RSA: func(privateKey []byte) (crypto.Signer, error) { return crypto.NewRSASigner(privateKey) },
	})
	fs := &failingStore{}
	srv := NewServer(ServerParams{KeyGeneratorStore: kg, SignerStore: ss, DeviceStore: fs})
	body := CreateSignatureDeviceRequest{Algorithm: crypto.RSA, Label: "x"}
	rr := doJSONReq(t, srv.CreateSignatureDevice, http.MethodPost, "/api/v0/signature-device", nil, body)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
	var erresp ErrorResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &erresp)
	if len(erresp.Errors) == 0 || !strings.Contains(erresp.Errors[0], "Unable to save signature device") {
		t.Fatalf("unexpected error response: %+v", erresp)
	}
}

func TestListSignatureDevices_Success(t *testing.T) {
	srv := newTestServer(t)
	// Pre-populate two devices
	for _, alg := range []crypto.SignatureAlgorithm{crypto.RSA, crypto.ECC} {
		dev, err := domain.NewSignatureDevice(srv.keyGeneratorStore, srv.signerStore, alg, string(alg)+"-label")
		if err != nil {
			t.Fatalf("prep device: %v", err)
		}
		if err := srv.deviceStore.Add(dev); err != nil {
			t.Fatalf("add: %v", err)
		}
	}
	rr := doJSONReq(t, srv.ListSignatureDevices, http.MethodGet, "/api/v0/signature-device", nil, nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var resp Response
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	// decode into slice
	b, _ := json.Marshal(resp.Data)
	var list []map[string]any
	if err := json.Unmarshal(b, &list); err != nil {
		t.Fatalf("remarshal: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("expected 2 devices, got %d", len(list))
	}
	for _, item := range list {
		if item["id"].(string) == "" || item["label"].(string) == "" {
			t.Fatalf("missing fields in item: %+v", item)
		}
	}
}

func TestGetSignatureDevice_Success(t *testing.T) {
	srv := newTestServer(t)
	dev, err := domain.NewSignatureDevice(srv.keyGeneratorStore, srv.signerStore, crypto.RSA, "lbl")
	if err != nil {
		t.Fatalf("create device: %v", err)
	}
	if err := srv.deviceStore.Add(dev); err != nil {
		t.Fatalf("add: %v", err)
	}
	url := "/api/v0/signature-device/" + dev.GetIDStr()
	rr := doJSONReq(t, srv.GetSignatureDevice, http.MethodGet, "/api/v0/signature-device/{id}", &url, nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestGetSignatureDevice_MissingID(t *testing.T) {
	srv := newTestServer(t)
	rr := doJSONReq(t, srv.GetSignatureDevice, http.MethodGet, "/api/v0/signature-device/", nil, nil)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
	var erresp ErrorResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &erresp)
	if len(erresp.Errors) == 0 || erresp.Errors[0] != "id is required" {
		t.Fatalf("unexpected error response: %+v", erresp)
	}
}

func TestGetSignatureDevice_NotFound(t *testing.T) {
	srv := newTestServer(t)
	url := "/api/v0/signature-device/doesnotexist"
	rr := doJSONReq(t, srv.GetSignatureDevice, http.MethodGet, "/api/v0/signature-device/{id}", &url, nil)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rr.Code)
	}
}
