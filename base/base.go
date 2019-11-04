package base

import (
	hd "github.com/btcsuite/btcutil/hdkeychain"
	"github.com/cpacia/multiwallet/database"
	iwallet "github.com/cpacia/wallet-interface"
	"time"
)

// DBTx satisfies the iwallet.Tx interface.
type DBTx struct {
	isClosed bool

	OnCommit func() error
}

// Commit will commit the transaction.
func (tx *DBTx) Commit() error {
	if tx.isClosed {
		panic("dbtx is closed")
	}
	if tx.OnCommit != nil {
		if err := tx.OnCommit(); err != nil {
			tx.Rollback()
			return err
		}
	}
	tx.isClosed = true
	return nil
}

// Rollback will rollback the transaction.
func (tx *DBTx) Rollback() error {
	if tx.isClosed {
		panic("dbtx is closed")
	}
	tx.OnCommit = nil
	tx.isClosed = true
	return nil
}

type WalletBase struct {
	ChainManager *ChainManager
	ChainClient  ChainClient
	KeyManager   *KeyManager
	DB           database.Database
	CoinType     iwallet.CoinType
}

// WalletExists should return whether the wallet exits or has been
// initialized.
func (w *WalletBase) WalletExists() bool {
	return true
}

func (w *WalletBase) CreateWallet(xpriv hd.ExtendedKey, pw []byte, birthday time.Time) error {
	return nil
}

// Open wallet will be called each time on OpenBazaar start. It
// will also be called after CreateWallet().
func (w *WalletBase) OpenWallet() error {
	return nil
}

// CloseWallet will be called when OpenBazaar shuts down.
func (w *WalletBase) CloseWallet() error {
	return nil
}

// CurrentAddress is called when requesting this wallet's receiving
// address. It is customary that the wallet return the first unused
// address and only return a different address after funds have been
// received on the address. This, however, is just a wallet implementation
// detail.
func (w *WalletBase) CurrentAddress() (iwallet.Address, error) {
	return w.KeyManager.CurrentAddress()
}

// NewAddress should return a new, never before used address. This is called
// by OpenBazaar to get a fresh address for a direct payment order. It
// associates this address with the order and assumes if a payment is received
// by this address that it is for the order. Failure to return a never before
// used address could put the order in a bad state.
//
// Wallets that only use a single address, like Ethereum, should save the
// passed in order ID locally such as to associate payments with orders.
func (w *WalletBase) NewAddress() (iwallet.Address, error) {
	return w.KeyManager.NewAddress()
}

// HasKey returns true if the wallet can spend from the given address.
func (w *WalletBase) HasKey(addr iwallet.Address) (bool, error) {
	return w.KeyManager.HasKey(addr)
}

// Begin returns a new database transaction. A transaction must only be used
// once. After Commit() or Rollback() is called the transaction can be discarded.
func (w *WalletBase) Begin() (iwallet.Tx, error) {
	return &DBTx{}, nil
}
