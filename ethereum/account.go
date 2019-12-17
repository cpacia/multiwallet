package ethereum

import (
	"crypto/ecdsa"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

// Account represents ethereum keystore
type Account struct {
	PrivateKey *ecdsa.PrivateKey
	Addr    common.Address
}

// Address returns the eth address
func (account *Account) Address() common.Address {
	return account.Addr
}

// SignTransaction will sign the txn
func (account *Account) SignTransaction(signer types.Signer, tx *types.Transaction) (*types.Transaction, error) {
	signature, err := crypto.Sign(signer.Hash(tx).Bytes(), account.PrivateKey)
	if err != nil {
		return nil, err
	}
	return tx.WithSignature(signer, signature)
}
