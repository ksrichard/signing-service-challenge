package api

import (
	"testing"

	"github.com/ksrichard/signing-service-challenge/crypto"
)

func TestCreateSignatureDeviceRequest_Validate(t *testing.T) {
	cases := []struct {
		alg     crypto.SignatureAlgorithm
		wantErr bool
	}{
		{crypto.RSA, false},
		{crypto.ECC, false},
		{"OTHER", true},
	}
	for _, c := range cases {
		req := &CreateSignatureDeviceRequest{Algorithm: c.alg}
		err := req.Validate()
		if c.wantErr && err == nil {
			t.Fatalf("expected error for alg %s", c.alg)
		}
		if !c.wantErr && err != nil {
			t.Fatalf("unexpected error for alg %s: %v", c.alg, err)
		}
	}
}

func TestSignTxRequest_Validate(t *testing.T) {
	// missing fields
	if err := (&SignTxRequest{}).Validate(); err == nil {
		t.Fatalf("expected error when both fields missing")
	}
	if err := (&SignTxRequest{DeviceID: " ", Data: "x"}).Validate(); err == nil {
		t.Fatalf("expected error when deviceId is blank")
	}
	if err := (&SignTxRequest{DeviceID: "id", Data: "   "}).Validate(); err == nil {
		t.Fatalf("expected error when data is blank")
	}
	// ok
	if err := (&SignTxRequest{DeviceID: "id", Data: "payload"}).Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
