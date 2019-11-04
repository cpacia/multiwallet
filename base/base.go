package base

import (
	"github.com/cpacia/multiwallet/database"
	iwallet "github.com/cpacia/wallet-interface"
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
	DB           database.Database
}

// Begin returns a new database transaction. A transaction must only be used
// once. After Commit() or Rollback() is called the transaction can be discarded.
func (w *WalletBase) Begin() (iwallet.Tx, error) {
	return &DBTx{}, nil
}
