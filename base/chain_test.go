package base

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"github.com/btcsuite/btcd/chaincfg"
	hd "github.com/btcsuite/btcutil/hdkeychain"
	"github.com/cpacia/multiwallet/database"
	"github.com/cpacia/multiwallet/database/sqlitedb"
	iwallet "github.com/cpacia/wallet-interface"
	"github.com/op/go-logging"
	"strings"
	"testing"
	"time"
)

func newTestChain() (*ChainManager, *MockChainClient, error) {
	db, err := sqlitedb.NewMemoryDB()
	if err != nil {
		return nil, nil, err
	}

	if err := database.InitializeDatabase(db); err != nil {
		return nil, nil, err
	}

	masterPrivKey, err := hd.NewMaster(make([]byte, 32), &chaincfg.MainNetParams)
	if err != nil {
		return nil, nil, err
	}

	masterPubKey, err := masterPrivKey.Neuter()
	if err != nil {
		return nil, nil, err
	}

	err = db.Update(func(tx database.Tx) error {
		return tx.Save(&database.CoinRecord{
			MasterPriv:         masterPrivKey.String(),
			EncryptedMasterKey: false,
			MasterPub:          masterPubKey.String(),
			Coin:               iwallet.CtMock,
			BestBlockHeight:    0,
			BestBlockID:        strings.Repeat("0", 64),
		})
	})
	if err != nil {
		return nil, nil, err
	}

	keychain, err := NewKeychain(db, iwallet.CtMock, func(key *hd.ExtendedKey) (iwallet.Address, error) {
		h := sha256.Sum256([]byte(key.String()))
		return iwallet.NewAddress(hex.EncodeToString(h[:]), iwallet.CtMock), nil
	})
	if err != nil {
		return nil, nil, err
	}

	log := logging.MustGetLogger("chain")

	client := NewMockChainClient()

	config := &ChainConfig{
		Client:             client,
		DB:                 db,
		Keychain:           keychain,
		CoinType:           iwallet.CtMock,
		Logger:             log,
		TxSubscriptionChan: nil,
		EventBus:           NewBus(),
	}

	return NewChainManager(config), client, nil
}

func TestChainManager_Start(t *testing.T) {
	// With this test we will make sure the chain starts correctly
	// even after experiencing an API failure.
	chain, client, err := newTestChain()
	if err != nil {
		t.Fatal(err)
	}

	sub, err := chain.eventBus.Subscribe(&ChainStartedEvent{})
	if err != nil {
		t.Fatal(err)
	}

	client.SetErrorResponse(errors.New("bad start"))

	chain.Start()
	defer chain.Stop()
	defer chain.db.Close()

	time.AfterFunc(time.Second, func() { client.SetErrorResponse(nil) })

	select {
	case <-sub.Out():
	case <-time.After(time.Second * 10):
		t.Fatal("Timed out waiting for start")
	}
}

func TestChainManager_Stop(t *testing.T) {
	// With this test we will make sure the best block is updated
	// on stop.
	chain, client, err := newTestChain()
	if err != nil {
		t.Fatal(err)
	}

	sub, err := chain.eventBus.Subscribe(&ChainStartedEvent{})
	if err != nil {
		t.Fatal(err)
	}

	blockSub, err := chain.eventBus.Subscribe(&BlockReceivedEvent{})
	if err != nil {
		t.Fatal(err)
	}

	chain.Start()
	defer chain.db.Close()

	select {
	case <-sub.Out():
	case <-time.After(time.Second * 10):
		t.Fatal("Timed out waiting for start")
	}

	client.GenerateBlock()

	select {
	case <-blockSub.Out():
	case <-time.After(time.Second * 10):
		t.Fatal("Timed out waiting to process block")
	}

	chain.Stop()

	var record database.CoinRecord
	err = chain.db.View(func(tx database.Tx) error {
		return tx.Read().Where("coin=?", chain.coinType.CurrencyCode()).Find(&record).Error
	})
	if err != nil {
		t.Fatal(err)
	}
	if record.BestBlockID != client.blocks[len(client.blocks)-1].BlockID.String() {
		t.Errorf("Saved incorrect block ID. Expected %s, got %s", client.blocks[len(client.blocks)-1].BlockID.String(), record.BestBlockID)
	}

	if record.BestBlockHeight != client.blocks[len(client.blocks)-1].Height {
		t.Errorf("Saved incorrect block height. Expected %d, got %d", client.blocks[len(client.blocks)-1].Height, record.BestBlockHeight)
	}
}

func TestChainManager_initializeChain(t *testing.T) {
	chain, client, err := newTestChain()
	if err != nil {
		t.Fatal(err)
	}
	defer chain.db.Close()

	client.GenerateBlock()
	client.GenerateBlock()

	txSub, blockSub, bestHeight, err := chain.initializeChain(iwallet.BlockInfo{}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	if txSub == nil {
		t.Error("Transaction Subscription is nil")
	}
	if blockSub == nil {
		t.Error("Block Subscription is nil")
	}

	if bestHeight != 0 {
		t.Errorf("Expected height of 0 got %d", bestHeight)
	}
}

func TestChainManager_ScanAndUpdate(t *testing.T) {
	chain, client, err := newTestChain()
	if err != nil {
		t.Fatal(err)
	}
	defer chain.db.Close()

	addrs, err := chain.keychain.GetAddresses()
	if err != nil {
		t.Fatal(err)
	}

	var (
		tx0 = NewMockTransaction(nil, &addrs[0])
		tx1 = NewMockTransaction(&tx0.To[0], nil)
		tx2 = NewMockTransaction(nil, &addrs[1])
		tx3 = NewMockTransaction(nil, nil)
		txs = []iwallet.Transaction{tx0, tx1, tx2, tx3}
	)

	for _, tx := range txs {
		client.txIndex[tx.ID] = tx

		for _, from := range tx.From {
			client.addrIndex[from.Address] = append(client.addrIndex[from.Address], tx)
		}
		for _, to := range tx.To {
			client.addrIndex[to.Address] = append(client.addrIndex[to.Address], tx)
		}
	}

	sub, err := chain.eventBus.Subscribe(&ScanCompleteEvent{})
	if err != nil {
		t.Fatal(err)
	}

	chain.Start()
	defer chain.Stop()

	select {
	case <-sub.Out():
	case <-time.After(time.Second * 10):
		t.Fatal("Timed out waiting for scan")
	}

	var savedTxs []database.TransactionRecord
	err = chain.db.View(func(tx database.Tx) error {
		return tx.Read().Where("coin=?", iwallet.CtMock).Find(&savedTxs).Error
	})
	if err != nil {
		t.Fatal(err)
	}

	if len(savedTxs) != 3 {
		t.Errorf("Expected 3 transactions, got %d", len(savedTxs))
	}

	ucSub, err := chain.eventBus.Subscribe(&UpdateUnconfirmedCompleteEvent{})
	if err != nil {
		t.Fatal(err)
	}

	client.GenerateBlock()

	select {
	case <-ucSub.Out():
	case <-time.After(time.Second * 10):
		t.Fatal("Timed out waiting for unconfirms to update")
	}

	var savedTxs2 []database.TransactionRecord
	err = chain.db.View(func(tx database.Tx) error {
		return tx.Read().Where("coin=?", iwallet.CtMock).Find(&savedTxs2).Error
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, tx := range savedTxs2 {
		if tx.BlockHeight == 0 {
			t.Error("Failed to update transaction height")
		}

		txn, err := tx.Transaction()
		if err != nil {
			t.Fatal(err)
		}

		if txn.Height == 0 {
			t.Error("Failed to update transaction height in serialized transaction")
		}

		if txn.BlockInfo == nil {
			t.Fatal("Block info is nil")
		}

		if txn.BlockInfo.Height != client.blocks[1].Height {
			t.Errorf("Incrrect height saved. Expected %d, got %d", client.blocks[1].Height, txn.BlockInfo.Height)
		}

		if txn.BlockInfo.BlockID != client.blocks[1].BlockID {
			t.Errorf("Incrrect height block ID. Expected %s, got %s", client.blocks[1].BlockID, txn.BlockInfo.BlockID)
		}
	}

	var utxos []database.UtxoRecord
	err = chain.db.View(func(tx database.Tx) error {
		return tx.Read().Where("coin=?", iwallet.CtMock).Find(&utxos).Error
	})
	if err != nil {
		t.Fatal(err)
	}

	if len(utxos) != 1 {
		t.Fatalf("Incorrect number of utxos. Expected 1, got %d", len(utxos))
	}

	if utxos[0].Height == 0 {
		t.Error("Failed to update utxo height")
	}

	if utxos[0].Outpoint != hex.EncodeToString(txs[2].To[0].ID) {
		t.Errorf("Incorrect outpoint. Expected %s, got %s", hex.EncodeToString(txs[2].To[0].ID), utxos[0].Outpoint)
	}

	if utxos[0].Amount != txs[2].To[0].Amount.String() {
		t.Errorf("Incorrect amount. Expected %s, got %s", txs[2].To[0].Amount.String(), utxos[0].Amount)
	}
}
