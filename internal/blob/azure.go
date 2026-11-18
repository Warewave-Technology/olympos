package blob

import (
	"context"
	"errors"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/google/uuid"

	"github.com/Warewave-Technology/olympos/internal/secrets"
	"github.com/Warewave-Technology/olympos/internal/store"
)

// NewResolver returns the Azure Blob resolver for destinations rows.
// STUB: replaced by the destinations implementation (M2).
func NewResolver(db *store.DB, kv secrets.KeyVault, env *secrets.Envelope, cred azcore.TokenCredential) Resolver {
	return stub{}
}

type stub struct{}

func (stub) ForDestination(context.Context, uuid.UUID) (Writer, error) {
	return nil, errors.New("blob storage not implemented yet")
}
