package persistence

import (
	"github.com/ksrichard/signing-service-challenge/domain"
)

type SignatureDeviceStore interface {
	Add(device *domain.SignatureDevice) error
	Get(id string) (*domain.SignatureDevice, error)
	List() ([]*domain.SignatureDevice, error)
}
