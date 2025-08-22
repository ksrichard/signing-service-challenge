package persistence

import (
	"errors"
	"testing"

	"github.com/ksrichard/signing-service-challenge/crypto"
	"github.com/ksrichard/signing-service-challenge/domain"
)

// helper to create a new device for tests
func newTestDevice(t *testing.T, label string) *domain.SignatureDevice {
	T := t
	T.Helper()
	kg := crypto.NewKeyGeneratorStore(map[crypto.SignatureAlgorithm]crypto.KeyGenerator{
		crypto.RSA: &crypto.RSAGenerator{},
	})
	ss := crypto.NewSignerStore(map[crypto.SignatureAlgorithm]crypto.SignerCreateFunc{
		crypto.RSA: func(privateKey []byte) (crypto.Signer, error) { return crypto.NewRSASigner(privateKey) },
	})
	dev, err := domain.NewSignatureDevice(&kg, &ss, crypto.RSA, label)
	if err != nil {
		T.Fatalf("failed to create signature device: %v", err)
	}
	return dev
}

func TestInMemorySignatureDeviceStore_AddGetList(t *testing.T) {
	store := NewInMemorySignatureDeviceStore()

	dev1 := newTestDevice(t, "one")
	dev2 := newTestDevice(t, "two")

	if err := store.Add(dev1); err != nil {
		t.Fatalf("Add(dev1) error: %v", err)
	}
	if err := store.Add(dev2); err != nil {
		t.Fatalf("Add(dev2) error: %v", err)
	}

	// Get
	got1, err := store.Get(dev1.GetIDStr())
	if err != nil {
		t.Fatalf("Get(dev1) error: %v", err)
	}
	if got1 != dev1 {
		t.Fatalf("Get returned unexpected device pointer")
	}

	// List (order not guaranteed)
	list, err := store.List()
	if err != nil {
		t.Fatalf("List() error: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("expected list length 2, got %d", len(list))
	}

	// ensure both IDs present
	found1, found2 := false, false
	for _, d := range list {
		if d.GetIDStr() == dev1.GetIDStr() {
			found1 = true
		}
		if d.GetIDStr() == dev2.GetIDStr() {
			found2 = true
		}
	}
	if !found1 || !found2 {
		t.Fatalf("list did not contain both devices: found1=%v found2=%v", found1, found2)
	}
}

func TestInMemorySignatureDeviceStore_Get_NotFound(t *testing.T) {
	store := NewInMemorySignatureDeviceStore()
	_, err := store.Get("doesnotexist")
	if err == nil {
		t.Fatalf("expected error for missing device, got nil")
	}
	if !errors.Is(err, ErrDeviceNotFound) {
		t.Fatalf("expected ErrDeviceNotFound, got %v", err)
	}
}
