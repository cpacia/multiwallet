package base

import (
	"encoding/hex"
	hd "github.com/btcsuite/btcutil/hdkeychain"
	"github.com/cpacia/multiwallet/database"
	iwallet "github.com/cpacia/wallet-interface"
	"github.com/jinzhu/gorm"
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

type subscription struct {
	blockSub chan iwallet.BlockInfo
	txSub    chan iwallet.Transaction
}

type WalletBase struct {
	ChainManager *ChainManager
	ChainClient  ChainClient
	KeyManager   *KeyManager
	DB           database.Database
	CoinType     iwallet.CoinType

	subscriptionChan chan *subscription

	done chan struct{}
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
	blockSub, err := w.ChainClient.SubscribeBlocks()
	if err != nil {
		return err
	}

	go func() {
		var (
			blockSubs []chan iwallet.BlockInfo
			txSubs    []chan iwallet.Transaction
		)

		for {
			select {
			case sub := <-w.subscriptionChan:
				if sub.blockSub != nil {
					blockSubs = append(blockSubs, sub.blockSub)
				}
				if sub.txSub != nil {
					txSubs = append(txSubs, sub.txSub)
				}
			case blockInfo := <-blockSub.Out:
				for _, sub := range blockSubs {
					sub <- blockInfo
				}
			case tx := <-w.ChainManager.subscriptionChan:
				for _, sub := range txSubs {
					sub <- tx
				}
			case <-w.done:
				return
			}
		}
	}()
	return nil
}

// CloseWallet will be called when OpenBazaar shuts down.
func (w *WalletBase) CloseWallet() error {
	return nil
}

// BlockchainInfo returns the best hash and height of the chain.
func (w *WalletBase) BlockchainInfo() (iwallet.BlockInfo, error) {
	return w.ChainManager.BestBlock(), nil
}

// CurrentAddress is called when requesting this wallet's receiving
// address. It is customary that the wallet return the first unused
// address and only return a different address after funds have been
// received on the address. This, however, is just a wallet implementation
// detail.
func (w *WalletBase) CurrentAddress() (iwallet.Address, error) {
	return w.KeyManager.CurrentAddress(false)
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
	return w.KeyManager.NewAddress(false)
}

// HasKey returns true if the wallet can spend from the given address.
func (w *WalletBase) HasKey(addr iwallet.Address) (bool, error) {
	return w.KeyManager.HasKey(addr)
}

// GetTransaction returns a transaction given it's ID.
func (w *WalletBase) GetTransaction(id iwallet.TransactionID) (iwallet.Transaction, error) {
	var record database.TransactionRecord
	err := w.DB.View(func(tx database.Tx) error {
		return tx.Read().Where("coin=?", w.CoinType.CurrencyCode()).Where("txid=?", id.String()).First(&record).Error
	})
	if err == nil {
		return record.Transaction()
	}
	return w.ChainClient.GetTransaction(id)
}

// Transactions returns a slice of this wallet's transactions.
func (w *WalletBase) Transactions() ([]iwallet.Transaction, error) {
	var records []database.TransactionRecord
	err := w.DB.View(func(tx database.Tx) error {
		return tx.Read().Where("coin=?", w.CoinType.CurrencyCode()).Find(&records).Error
	})
	if err != nil {
		return nil, err
	}
	txs := make([]iwallet.Transaction, len(records))
	for i, rec := range records {
		txs[i], err = rec.Transaction()
		if err != nil {
			return nil, err
		}
	}
	return txs, nil
}

// Balance should return the confirmed and unconfirmed balance for the wallet.
func (w *WalletBase) Balance() (unconfirmed iwallet.Amount, confirmed iwallet.Amount, err error) {
	err = w.DB.View(func(dbtx database.Tx) error {
		var (
			utxoRecords []database.UtxoRecord
			txRecords   []database.TransactionRecord
			txMap       = make(map[iwallet.TransactionID]iwallet.Transaction)
		)
		err := dbtx.Read().Where("coin=?", w.CoinType.CurrencyCode()).Find(&utxoRecords).Error
		if err != nil {
			return err
		}
		err = dbtx.Read().Where("coin=?", w.CoinType.CurrencyCode()).Find(&txRecords).Error
		if err != nil && !gorm.IsRecordNotFoundError(err) {
			return err
		}

		for _, record := range txRecords {
			tx, err := record.Transaction()
			if err != nil {
				return err
			}
			txMap[tx.ID] = tx
		}

		for _, utxo := range utxoRecords {
			if utxo.Height > 0 {
				confirmed.Add(iwallet.NewAmount(utxo.Amount))
			} else {
				if checkIfStxoIsConfirmed(iwallet.TransactionID(utxo.Outpoint[:64]), txMap) {
					confirmed.Add(iwallet.NewAmount(utxo.Amount))
				} else {
					unconfirmed.Add(iwallet.NewAmount(utxo.Amount))
				}
			}
		}
		return nil
	})
	if err != nil && !gorm.IsRecordNotFoundError(err) {
		return
	} else if gorm.IsRecordNotFoundError(err) {
		return unconfirmed, confirmed, nil
	}
	return unconfirmed, confirmed, nil
}

func checkIfStxoIsConfirmed(txid iwallet.TransactionID, txMap map[iwallet.TransactionID]iwallet.Transaction) bool {
	tx, ok := txMap[txid]
	if !ok {
		return false
	}

	// For each input, recursively check if confirmed
	inputsConfirmed := true
	for _, from := range tx.From {
		checkTx, ok := txMap[iwallet.TransactionID(hex.EncodeToString(from.ID[:32]))]
		if ok { // Is an stxo. If confirmed we can return true. If no, we need to check the dependency.
			if checkTx.Height == 0 {
				if !checkIfStxoIsConfirmed(iwallet.TransactionID(hex.EncodeToString(from.ID[:32])), txMap) {
					inputsConfirmed = false
				}
			}
		} else { // We don't have the tx in our db so it can't be an stxo. Return false.
			return false
		}
	}
	return inputsConfirmed
}

// WatchAddress is used by the escrow system to tell the wallet to listen
// on the escrow address. It's expected that payments into and spends from
// this address will be pushed back to OpenBazaar.
//
// Note a database transaction is used here. Same rules of Commit() and
// Rollback() apply.
func (w *WalletBase) WatchAddress(tx iwallet.Tx, addr iwallet.Address) error {
	dbtx := tx.(*DBTx)
	dbtx.OnCommit = func() error {
		return w.DB.Update(func(tx database.Tx) error {
			err := tx.Save(&database.WatchedAddressRecord{
				Addr: addr.String(),
				Coin: w.CoinType.CurrencyCode(),
			})
			if err != nil {
				return err
			}
			w.ChainManager.AddWatchOnly(addr)
			return nil
		})
	}
	return nil
}

// SubscribeTransactions returns a chan over which the wallet is expected
// to push both transactions relevant for this wallet as well as transactions
// sending to or spending from a watched address.
func (w *WalletBase) SubscribeTransactions() <-chan iwallet.Transaction {
	ch := make(chan iwallet.Transaction)
	w.subscriptionChan <- &subscription{
		txSub: ch,
	}
	return ch
}

// SubscribeBlocks returns a chan over which the wallet is expected
// to push info about new blocks when they arrive.
func (w *WalletBase) SubscribeBlocks() <-chan iwallet.BlockInfo {
	ch := make(chan iwallet.BlockInfo)
	w.subscriptionChan <- &subscription{
		blockSub: ch,
	}
	return ch
}

// Begin returns a new database transaction. A transaction must only be used
// once. After Commit() or Rollback() is called the transaction can be discarded.
func (w *WalletBase) Begin() (iwallet.Tx, error) {
	return &DBTx{}, nil
}
