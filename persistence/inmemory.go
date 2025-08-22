package persistence

import (
	"errors"
	"sync"

	"github.com/ksrichard/signing-service-challenge/domain"
)

var (
	ErrDeviceNotFound = errors.New("signature device not found")
)

type InMemorySignatureDeviceStore struct {
	sync.RWMutex
	devices map[string]*domain.SignatureDevice
}

func NewInMemorySignatureDeviceStore() *InMemorySignatureDeviceStore {
	return &InMemorySignatureDeviceStore{
		devices: make(map[string]*domain.SignatureDevice),
	}
}

func (s *InMemorySignatureDeviceStore) Add(device *domain.SignatureDevice) error {
	s.Lock()
	defer s.Unlock()
	s.devices[device.GetIDStr()] = device
	return nil
}

func (s *InMemorySignatureDeviceStore) Get(id string) (*domain.SignatureDevice, error) {
	s.RLock()
	defer s.RUnlock()
	if ok := s.devices[id] != nil; !ok {
		return nil, ErrDeviceNotFound
	}
	return s.devices[id], nil
}

func (s *InMemorySignatureDeviceStore) List() ([]*domain.SignatureDevice, error) {
	s.RLock()
	defer s.RUnlock()
	var result []*domain.SignatureDevice
	for _, device := range s.devices {
		result = append(result, device)
	}
	return result, nil
}
