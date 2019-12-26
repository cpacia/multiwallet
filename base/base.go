package base

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/btcsuite/btcutil/coinset"
	hd "github.com/btcsuite/btcutil/hdkeychain"
	expbackoff "github.com/cenkalti/backoff"
	"github.com/cpacia/multiwallet/database"
	iwallet "github.com/cpacia/wallet-interface"
	"github.com/gcash/bchd/wire"
	"github.com/jinzhu/gorm"
	"github.com/op/go-logging"
	"strings"
	"sync"
	"time"
)

var ErrInsufficientFunds = errors.New("insufficient funds")

// WalletConfig is struct that can be used pass into the constructor
// for each coin's wallet.
type WalletConfig struct {
	DB        database.Database
	Logger    *logging.Logger
	Testnet   bool
	ClientUrl string
	FeeUrl    string
}

// DBTx satisfies the iwallet.Tx interface.
type DBTx struct {
	isClosed bool
	mtx      sync.Mutex

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
	tx.mtx.Unlock()
	return nil
}

// Rollback will rollback the transaction.
func (tx *DBTx) Rollback() error {
	if tx.isClosed {
		panic("dbtx is closed")
	}
	tx.OnCommit = nil
	tx.isClosed = true
	tx.mtx.Unlock()
	return nil
}

type subscription struct {
	blockSub chan iwallet.BlockInfo
	txSub    chan iwallet.Transaction
}

// WalletBase is a base class that wallets can extended by the individual
// wallets. It contains a little over half the interface methods so the only
// remaining methods that need to be implemented by each coin's package are
// the method's specific to signing and building transactions.
type WalletBase struct {
	ChainManager *ChainManager
	ChainClient  ChainClient
	Keychain     *Keychain
	KeychainOpts []KeychainOption
	DB           database.Database
	CoinType     iwallet.CoinType
	Logger       *logging.Logger
	AddressFunc  func(key *hd.ExtendedKey) (iwallet.Address, error)

	rebroacaster     *Rebroadcaster
	subscriptionChan chan *subscription
	txMtx            sync.Mutex

	Done chan struct{}
}

// Begin returns a new database transaction. A transaction must only be used
// once. After Commit() or Rollback() is called the transaction can be discarded.
func (w *WalletBase) Begin() (iwallet.Tx, error) {
	w.txMtx.Lock()
	return &DBTx{mtx: w.txMtx}, nil
}

// WalletExists should return whether the wallet exits or has been
// initialized.
func (w *WalletBase) WalletExists() bool {
	err := w.DB.View(func(tx database.Tx) error {
		var rec database.CoinRecord
		return tx.Read().Where("coin = ?", w.CoinType.CurrencyCode()).Find(&rec).Error
	})
	return err == nil
}

// CreateWallet should initialize the wallet. This will be called by
// OpenBazaar if WalletExists() returns false.
//
// The xPriv may be used to create a bip44 keychain. The xPriv is
// `cointype` level in the bip44 path. For example in the following
// path the wallet should only derive the paths after `account` as
// m, purpose', and coin_type' are kept private by OpenBazaar so this
// wallet cannot derive keys from other wallets.
//
// m / purpose' / coin_type' / account' / change / address_index
//
// The birthday can be used determine where to sync state from if
// appropriate.
//
// If the wallet does not implement WalletCrypter then pw will be
// nil. Otherwise it should be used to encrypt the private keys.
func (w *WalletBase) CreateWallet(xpriv hd.ExtendedKey, pw []byte, birthday time.Time) error {
	xpub, err := xpriv.Neuter()
	if err != nil {
		return err
	}

	err = w.DB.View(func(tx database.Tx) error {
		var rec database.CoinRecord
		return tx.Read().Where("coin = ?", w.CoinType.CurrencyCode()).Find(&rec).Error
	})
	if err != nil && !gorm.IsRecordNotFoundError(err) {
		return err
	} else if err == nil {
		return fmt.Errorf("wallet already exists for coin %s", w.CoinType.CurrencyCode())
	}

	return w.DB.Update(func(tx database.Tx) error {
		return tx.Save(&database.CoinRecord{
			MasterPriv:         xpriv.String(),
			EncryptedMasterKey: false,
			MasterPub:          xpub.String(),
			Coin:               w.CoinType.CurrencyCode(),
			Birthday:           birthday,
			BestBlockHeight:    0,
			BestBlockID:        strings.Repeat("0", 64),
		})
	})
}

// Open wallet will be called each time on OpenBazaar start. It
// will also be called after CreateWallet().
func (w *WalletBase) OpenWallet() error {
	keychain, err := NewKeychain(w.DB, w.CoinType, w.AddressFunc, w.KeychainOpts...)
	if err != nil {
		return err
	}
	w.Keychain = keychain
	w.txMtx = sync.Mutex{}
	w.subscriptionChan = make(chan *subscription)

	txSubChan := make(chan iwallet.Transaction)

	config := &ChainConfig{
		Client:             w.ChainClient,
		DB:                 w.DB,
		Keychain:           keychain,
		CoinType:           w.CoinType,
		Logger:             w.Logger,
		TxSubscriptionChan: txSubChan,
	}

	w.ChainManager = NewChainManager(config)
	if err := w.ChainManager.Start(); err != nil {
		return err
	}

	go func() {
		var (
			blockSub1  *BlockSubscription
			blockSub2  *BlockSubscription
			bo         = expbackoff.NewExponentialBackOff()
			err1, err2 error
		)
		for {
			blockSub1, err1 = w.ChainClient.SubscribeBlocks()
			blockSub2, err2 = w.ChainClient.SubscribeBlocks()
			if err1 != nil || err2 != nil {
				select {
				case <-time.After(bo.NextBackOff()):
					continue
				case <-w.Done:
					return
				}
			}
			break
		}

		w.rebroacaster = NewRebroadcaster(w.DB, w.Logger, w.CoinType, w.ChainClient.Broadcast, blockSub2)
		go w.rebroacaster.Start()

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
			case blockInfo := <-blockSub1.Out:
				for _, sub := range blockSubs {
					sub <- blockInfo
				}
			case tx := <-txSubChan:
				for _, sub := range txSubs {
					sub <- tx
				}
			case <-w.Done:
				return
			}
		}
	}()
	return nil
}

// CloseWallet will be called when OpenBazaar shuts down.
func (w *WalletBase) CloseWallet() error {
	w.ChainManager.Stop()
	if err := w.DB.Close(); err != nil {
		return err
	}
	if err := w.ChainClient.Close(); err != nil {
		return err
	}
	if w.rebroacaster != nil {
		w.rebroacaster.Stop()
	}

	close(w.Done)
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
	return w.Keychain.CurrentAddress(false)
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
	addr, err := w.Keychain.NewAddress(false)
	if err != nil {
		return addr, err
	}
	w.ChainManager.AddAddressSubscription(addr)
	return addr, nil
}

// HasKey returns true if the wallet can spend from the given address.
func (w *WalletBase) HasKey(addr iwallet.Address) (bool, error) {
	return w.Keychain.HasKey(addr)
}

// GetTransaction returns a transaction given it's ID.
func (w *WalletBase) GetTransaction(id iwallet.TransactionID) (iwallet.Transaction, error) {
	var record database.TransactionRecord
	err := w.DB.View(func(tx database.Tx) error {
		return tx.Read().Where("coin=?", w.CoinType.CurrencyCode()).Where("txid=?", id.String()).First(&record).Error
	})
	if err == nil {
		// We need to return the input metadata with this transaction. If it isn't stored with this
		// transaction in the database then we will need to use the API to get a copy of the transaction
		// with the input metadata.
		tx, err := record.Transaction()
		if err == nil {
			missingInputMetadata := false
			for _, in := range tx.From {
				if in.Address.String() == "" || in.Amount.String() == "" || in.Amount.Cmp(iwallet.NewAmount(0)) == 0 {
					missingInputMetadata = true
				}
			}
			if !missingInputMetadata {
				return tx, nil
			}
		}
	}

	backoff := expbackoff.NewExponentialBackOff()
	backoff.MaxElapsedTime = time.Second * 30

	for {
		tx, err := w.ChainClient.GetTransaction(id)
		if err == nil {
			return tx, nil
		}
		next := backoff.NextBackOff()
		if next == expbackoff.Stop {
			return tx, errors.New("timed out querying for address transactions")
		}
		select {
		case <-time.After(next):
			continue
		case <-w.Done:
			return tx, errors.New("wallet is closed")
		}
	}
}

// GetAddressTransactions returns the transactions sending to or spending from this address.
// Note this will only ever be called for an order's payment address transaction so for the
// purpose of this method the wallet only needs to be able to track transactions paid to a
// wallet address and any watched addresses.
func (w *WalletBase) GetAddressTransactions(addr iwallet.Address) ([]iwallet.Transaction, error) {
	backoff := expbackoff.NewExponentialBackOff()
	backoff.MaxElapsedTime = time.Second * 30

	for {
		txs, err := w.ChainClient.GetAddressTransactions(addr, 0)
		if err == nil {
			return txs, nil
		}
		next := backoff.NextBackOff()
		if next == expbackoff.Stop {
			return nil, errors.New("timed out querying for address transactions")
		}
		select {
		case <-time.After(next):
			continue
		case <-w.Done:
			return nil, errors.New("wallet is closed")
		}
	}
}

// Transactions returns a slice of this wallet's transactions. The transactions should
// be sorted last to first and the limit and offset respected. The offsetID means
// 'return transactions starting with the transaction after offsetID in the sorted list'
func (w *WalletBase) Transactions(limit int, offsetID iwallet.TransactionID) ([]iwallet.Transaction, error) {
	var records []database.TransactionRecord
	err := w.DB.View(func(tx database.Tx) error {
		if offsetID != "" {
			var rec database.TransactionRecord
			err := tx.Read().Where("coin=?", w.CoinType.CurrencyCode()).Where("txid=?", offsetID.String()).First(&rec).Error
			if err != nil {
				return err
			}
			return tx.Read().Where("coin=?", w.CoinType.CurrencyCode()).Where("timestamp < ?", rec.Timestamp).Order("timestamp desc").Limit(limit).Find(&records).Error
		}

		return tx.Read().Where("coin=?", w.CoinType.CurrencyCode()).Order("timestamp desc").Limit(limit).Find(&records).Error
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
				confirmed = confirmed.Add(iwallet.NewAmount(utxo.Amount))
			} else {
				if checkIfStxoIsConfirmed(iwallet.TransactionID(utxo.Outpoint[:64]), txMap) {
					confirmed = confirmed.Add(iwallet.NewAmount(utxo.Amount))
				} else {
					unconfirmed = unconfirmed.Add(iwallet.NewAmount(utxo.Amount))
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
func (w *WalletBase) WatchAddress(tx iwallet.Tx, addrs ...iwallet.Address) error {
	dbtx := tx.(*DBTx)
	dbtx.OnCommit = func() error {
		var updated []iwallet.Address
		err := w.DB.Update(func(tx database.Tx) error {
			for _, addr := range addrs {
				var addrRecord database.AddressRecord
				err := tx.Read().Where("coin=?", w.CoinType.CurrencyCode()).Where("addr=?", addr.String()).First(&addrRecord).Error
				if err == nil {
					// This is a wallet address. Likely from
					// an address request order.
					continue
				}

				var watchedRecord database.WatchedAddressRecord
				err = tx.Read().Where("coin=?", w.CoinType.CurrencyCode()).Where("addr=?", addr.String()).First(&watchedRecord).Error
				if err == nil {
					// We've previously saved this address before.
					// No need to do anything new.
					continue
				}

				err = tx.Save(&database.WatchedAddressRecord{
					Addr: addr.String(),
					Coin: w.CoinType.CurrencyCode(),
				})
				if err != nil {
					return err
				}
				updated = append(updated, addr)
			}
			return nil
		})
		if err != nil {
			return err
		}
		if len(updated) > 0 {
			w.ChainManager.AddWatchOnly(updated...)
		}
		return nil
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

// CanReleaseFunds returns whether the wallet can release the funds from escrow. This MUST
// return false if the wallet is encrypted or if there is insufficient coins in the wallet
// to pay the transaction fee/gas. This method should not actually move any funds.
func (w *WalletBase) CanReleaseFunds(txn iwallet.Transaction, signatures [][]iwallet.EscrowSignature, redeemScript []byte) (bool, error) {
	return true, nil
}

// SetPassphase is called after creating the wallet. It gives the wallet
// the opportunity to set up encryption of the private keys.
func (w *WalletBase) SetPassphase(pw []byte) error {
	return w.Keychain.SetPassphase(pw)
}

// ChangePassphrase is called in response to user action requesting the
// passphrase be changed. It is expected that this will return an error
// if the old password is incorrect.
func (w *WalletBase) ChangePassphrase(old, new []byte) error {
	return w.Keychain.ChangePassphrase(old, new)
}

// RemovePassphrase is called in response to user action requesting the
// passphrase be removed. It is expected that this will return an error
// if the old password is incorrect.
func (w *WalletBase) RemovePassphrase(pw []byte) error {
	return w.Keychain.RemovePassphrase(pw)
}

// Unlock is called just prior to calling Spend(). The wallet should
// decrypt the private key and hold the decrypted key in memory for
// the provided duration after which it should be purged from memory.
// If the provided password is incorrect it should error.
func (w *WalletBase) Unlock(pw []byte, howLong time.Duration) error {
	return w.Keychain.Unlock(pw, howLong)
}

// GatherCoins returns the full list of spendable coins in the wallet along
// with the key needed to spend. The wallet must be unlocked to use this
// function.
func (w *WalletBase) GatherCoins(dbtx database.Tx) (map[coinset.Coin]*hd.ExtendedKey, error) {
	var utxoRecords []database.UtxoRecord
	if err := dbtx.Read().Where("coin = ?", w.CoinType.CurrencyCode()).Find(&utxoRecords).Error; err != nil {
		return nil, err
	}

	bcInfo, err := w.BlockchainInfo()
	if err != nil {
		return nil, err
	}

	m := make(map[coinset.Coin]*hd.ExtendedKey)
	for _, u := range utxoRecords {
		var confirmations int64
		if u.Height > 0 {
			confirmations = int64(bcInfo.Height - u.Height)
		}

		var op wire.OutPoint
		ser, err := hex.DecodeString(u.Outpoint)
		if err != nil {
			return nil, err
		}
		if err := op.Deserialize(bytes.NewReader(ser)); err != nil {
			return nil, err
		}

		addr := iwallet.NewAddress(u.Address, w.CoinType)
		c, err := NewCoin(iwallet.TransactionID(op.Hash.String()), op.Index, iwallet.NewAmount(u.Amount), confirmations, addr)
		if err != nil {
			continue
		}

		key, err := w.Keychain.KeyForAddress(dbtx, addr, nil)
		if err != nil {
			continue
		}

		m[c] = key
	}
	return m, nil
}
