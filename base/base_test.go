package base

import (
	"encoding/hex"
	hd "github.com/btcsuite/btcutil/hdkeychain"
	"github.com/cpacia/multiwallet/database"
	"github.com/cpacia/multiwallet/database/sqlitedb"
	iwallet "github.com/cpacia/wallet-interface"
	"github.com/op/go-logging"
	"testing"
	"time"
)

func setupWallet() (*WalletBase, error) {
	db, err := sqlitedb.NewMemoryDB()
	if err != nil {
		return nil, err
	}
	if err := database.InitializeDatabase(db); err != nil {
		return nil, err
	}
	logger, err := logging.GetLogger("test")
	if err != nil {
		return nil, err
	}
	w := &WalletBase{
		ChainClient: NewMockChainClient(),
		Done:        make(chan struct{}),
		DB:          db,
		Logger:      logger,
		CoinType:    iwallet.CtMock,
		AddressFunc: newTestAddress,
	}

	return w, nil
}

func TestWalletBase_WalletExists(t *testing.T) {
	w, err := setupWallet()
	if err != nil {
		t.Fatal(err)
	}
	if w.WalletExists() {
		t.Error("Wallet exists")
	}

	xpriv, err := hd.NewKeyFromString("tprv8ZgxMBicQKsPeghT19pungdFLMJM2hMs3EEn5WtgobD7wuQSFQu4VNaEJXH9HS3RhhLT4wgZ3hj31m3kafuxhL9vfGTRtBVLSog4zjxW3L1")
	if err != nil {
		t.Fatal(err)
	}

	if err := w.CreateWallet(*xpriv, nil, time.Now()); err != nil {
		t.Fatal(err)
	}

	if !w.WalletExists() {
		t.Error("Wallet does not exist")
	}
}

func TestWalletBase_OpenCloseWallet(t *testing.T) {
	w, err := setupWallet()
	if err != nil {
		t.Fatal(err)
	}

	xpriv, err := hd.NewKeyFromString("tprv8ZgxMBicQKsPeghT19pungdFLMJM2hMs3EEn5WtgobD7wuQSFQu4VNaEJXH9HS3RhhLT4wgZ3hj31m3kafuxhL9vfGTRtBVLSog4zjxW3L1")
	if err != nil {
		t.Fatal(err)
	}

	if err := w.CreateWallet(*xpriv, nil, time.Now()); err != nil {
		t.Fatal(err)
	}

	if err := w.OpenWallet(); err != nil {
		t.Fatal(err)
	}

	if err := w.CloseWallet(); err != nil {
		t.Fatal(err)
	}
}

func TestWalletBase_Subscriptions(t *testing.T) {
	w, err := setupWallet()
	if err != nil {
		t.Fatal(err)
	}

	xpriv, err := hd.NewKeyFromString("tprv8ZgxMBicQKsPeghT19pungdFLMJM2hMs3EEn5WtgobD7wuQSFQu4VNaEJXH9HS3RhhLT4wgZ3hj31m3kafuxhL9vfGTRtBVLSog4zjxW3L1")
	if err != nil {
		t.Fatal(err)
	}

	if err := w.CreateWallet(*xpriv, nil, time.Now()); err != nil {
		t.Fatal(err)
	}

	if err := w.OpenWallet(); err != nil {
		t.Fatal(err)
	}
	<-time.After(time.Second)
	txSub := w.SubscribeTransactions()

	txid := "1234"
	w.ChainManager.subscriptionChan <- iwallet.Transaction{ID: iwallet.TransactionID(txid)}

	select {
	case tx := <-txSub:
		if tx.ID.String() != txid {
			t.Errorf("Expected txid %s, got %s", txid, tx.ID.String())
		}
	case <-time.After(time.Second * 10):
		t.Fatal("timed out waiting on channel")
	}

	blockSub := w.SubscribeBlocks()

	w.ChainClient.(*MockChainClient).GenerateBlock()

	select {
	case <-blockSub:
	case <-time.After(time.Second * 10):
		t.Fatal("timed out waiting on channel")
	}
}

func TestWalletBase_BlockchainInfo(t *testing.T) {
	w, err := setupWallet()
	if err != nil {
		t.Fatal(err)
	}

	xpriv, err := hd.NewKeyFromString("tprv8ZgxMBicQKsPeghT19pungdFLMJM2hMs3EEn5WtgobD7wuQSFQu4VNaEJXH9HS3RhhLT4wgZ3hj31m3kafuxhL9vfGTRtBVLSog4zjxW3L1")
	if err != nil {
		t.Fatal(err)
	}

	if err := w.CreateWallet(*xpriv, nil, time.Now()); err != nil {
		t.Fatal(err)
	}

	if err := w.OpenWallet(); err != nil {
		t.Fatal(err)
	}
	<-time.After(time.Second)

	w.ChainClient.(*MockChainClient).GenerateBlock()

	w.ChainManager.eventBus = NewBus()

	sub, err := w.ChainManager.eventBus.Subscribe(&BlockReceivedEvent{})
	if err != nil {
		t.Fatal(err)
	}

	select {
	case <-sub.Out():
	case <-time.After(time.Second * 10):
		t.Fatal("timed out waiting on channel")
	}

	info, err := w.BlockchainInfo()
	if err != nil {
		t.Fatal(err)
	}
	if info.Height != 1 {
		t.Errorf("Expected height 1 got %d", info.Height)
	}
}

func TestWalletBase_CurrentAddress(t *testing.T) {
	w, err := setupWallet()
	if err != nil {
		t.Fatal(err)
	}
	xpriv, err := hd.NewKeyFromString("tprv8ZgxMBicQKsPeghT19pungdFLMJM2hMs3EEn5WtgobD7wuQSFQu4VNaEJXH9HS3RhhLT4wgZ3hj31m3kafuxhL9vfGTRtBVLSog4zjxW3L1")
	if err != nil {
		t.Fatal(err)
	}

	if err := w.CreateWallet(*xpriv, nil, time.Now()); err != nil {
		t.Fatal(err)
	}

	if err := w.OpenWallet(); err != nil {
		t.Fatal(err)
	}

	current, err := w.CurrentAddress()
	if err != nil {
		t.Fatal(err)
	}

	expected := "9324aa9a2c341003a4880f70aad70868b2c9b82d84032751ae7ce73b80a19bd9"
	if expected != current.String() {
		t.Errorf("Expected address %s, got %s", expected, current.String())
	}

	err = w.DB.View(func(tx database.Tx) error {
		current, err = w.Keychain.CurrentAddressWithTx(tx, false)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}

	if expected != current.String() {
		t.Errorf("Expected address %s, got %s", expected, current.String())
	}
}

func TestWalletBase_NewAddress(t *testing.T) {
	w, err := setupWallet()
	if err != nil {
		t.Fatal(err)
	}
	xpriv, err := hd.NewKeyFromString("tprv8ZgxMBicQKsPeghT19pungdFLMJM2hMs3EEn5WtgobD7wuQSFQu4VNaEJXH9HS3RhhLT4wgZ3hj31m3kafuxhL9vfGTRtBVLSog4zjxW3L1")
	if err != nil {
		t.Fatal(err)
	}

	if err := w.CreateWallet(*xpriv, nil, time.Now()); err != nil {
		t.Fatal(err)
	}

	if err := w.OpenWallet(); err != nil {
		t.Fatal(err)
	}

	new, err := w.NewAddress()
	if err != nil {
		t.Fatal(err)
	}

	expected := "17cc476744c727797e141ae73dac379703697ecc8a223bee63ea4fddc171b28b"
	if expected != new.String() {
		t.Errorf("Expected address %s, got %s", expected, new.String())
	}

	addrs, err := w.Keychain.GetAddresses()
	if err != nil {
		t.Fatal(err)
	}
	if len(addrs) != 21 {
		t.Errorf("Expected 21 addresses got %d", len(addrs))
	}
}

func TestWalletBase_HasKey(t *testing.T) {
	w, err := setupWallet()
	if err != nil {
		t.Fatal(err)
	}
	xpriv, err := hd.NewKeyFromString("tprv8ZgxMBicQKsPeghT19pungdFLMJM2hMs3EEn5WtgobD7wuQSFQu4VNaEJXH9HS3RhhLT4wgZ3hj31m3kafuxhL9vfGTRtBVLSog4zjxW3L1")
	if err != nil {
		t.Fatal(err)
	}

	if err := w.CreateWallet(*xpriv, nil, time.Now()); err != nil {
		t.Fatal(err)
	}

	if err := w.OpenWallet(); err != nil {
		t.Fatal(err)
	}

	addrs, err := w.Keychain.GetAddresses()
	if err != nil {
		t.Fatal(err)
	}

	for _, addr := range addrs {
		has, err := w.HasKey(addr)
		if err != nil {
			t.Fatal(err)
		}
		if !has {
			t.Errorf("Address %s expected key to be found", addr)
		}
	}
}

func TestWalletBase_EncryptDecrypt(t *testing.T) {
	w, err := setupWallet()
	if err != nil {
		t.Fatal(err)
	}
	xpriv, err := hd.NewKeyFromString("tprv8ZgxMBicQKsPeghT19pungdFLMJM2hMs3EEn5WtgobD7wuQSFQu4VNaEJXH9HS3RhhLT4wgZ3hj31m3kafuxhL9vfGTRtBVLSog4zjxW3L1")
	if err != nil {
		t.Fatal(err)
	}

	if err := w.CreateWallet(*xpriv, nil, time.Now()); err != nil {
		t.Fatal(err)
	}

	if err := w.OpenWallet(); err != nil {
		t.Fatal(err)
	}

	addrs, err := w.Keychain.GetAddresses()
	if err != nil {
		t.Fatal(err)
	}

	if w.Keychain.IsEncrypted() {
		t.Fatal("Keychain is encrypted")
	}

	pw := []byte("let me in")
	if err := w.SetPassphase(pw); err != nil {
		t.Fatal(err)
	}

	if !w.Keychain.IsEncrypted() {
		t.Fatal("Keychain is not encrypted")
	}
	err = w.DB.Update(func(tx database.Tx) error {
		_, err := w.Keychain.KeyForAddress(tx, addrs[0], nil)
		return err
	})
	if err != ErrEncryptedKeychain {
		t.Errorf("Expected ErrEncryptedKeychain, got %s", err)
	}

	if err := w.Unlock([]byte("wrong password"), time.Second); err == nil {
		t.Errorf("Expected decryption error got nil")
	}

	if err := w.Unlock(pw, time.Second); err != nil {
		t.Fatal(err)
	}

	if w.Keychain.IsEncrypted() {
		t.Fatal("Keychain is encrypted")
	}
	err = w.DB.Update(func(tx database.Tx) error {
		_, err := w.Keychain.KeyForAddress(tx, addrs[0], nil)
		return err
	})
	if err != nil {
		t.Errorf("Expected nil, got %s", err)
	}

	<-time.After(time.Second * 2)
	if !w.Keychain.IsEncrypted() {
		t.Fatal("Keychain is not encrypted")
	}
	err = w.DB.Update(func(tx database.Tx) error {
		_, err := w.Keychain.KeyForAddress(tx, addrs[0], nil)
		return err
	})
	if err != ErrEncryptedKeychain {
		t.Errorf("Expected ErrEncryptedKeychain, got %s", err)
	}
}

func TestWalletBase_ChangeRemovePassphrase(t *testing.T) {
	w, err := setupWallet()
	if err != nil {
		t.Fatal(err)
	}
	xpriv, err := hd.NewKeyFromString("tprv8ZgxMBicQKsPeghT19pungdFLMJM2hMs3EEn5WtgobD7wuQSFQu4VNaEJXH9HS3RhhLT4wgZ3hj31m3kafuxhL9vfGTRtBVLSog4zjxW3L1")
	if err != nil {
		t.Fatal(err)
	}

	if err := w.CreateWallet(*xpriv, nil, time.Now()); err != nil {
		t.Fatal(err)
	}

	if err := w.OpenWallet(); err != nil {
		t.Fatal(err)
	}

	addrs, err := w.Keychain.GetAddresses()
	if err != nil {
		t.Fatal(err)
	}

	if w.Keychain.IsEncrypted() {
		t.Fatal("Keychain is encrypted")
	}

	pw := []byte("let me in")
	if err := w.SetPassphase(pw); err != nil {
		t.Fatal(err)
	}

	if !w.Keychain.IsEncrypted() {
		t.Fatal("Keychain is not encrypted")
	}
	err = w.DB.Update(func(tx database.Tx) error {
		_, err := w.Keychain.KeyForAddress(tx, addrs[0], nil)
		return err
	})
	if err != ErrEncryptedKeychain {
		t.Errorf("Expected ErrEncryptedKeychain, got %s", err)
	}

	pw2 := []byte("let me in 2")
	if err := w.ChangePassphrase(pw, pw2); err != nil {
		t.Fatal(err)
	}

	if err := w.Unlock(pw2, time.Second); err != nil {
		t.Fatal(err)
	}

	if w.Keychain.IsEncrypted() {
		t.Fatal("Keychain is encrypted")
	}
	err = w.DB.Update(func(tx database.Tx) error {
		_, err := w.Keychain.KeyForAddress(tx, addrs[0], nil)
		return err
	})
	if err != nil {
		t.Errorf("Expected nil, got %s", err)
	}

	<-time.After(time.Second)
	if !w.Keychain.IsEncrypted() {
		t.Fatal("Keychain is not encrypted")
	}
	err = w.DB.Update(func(tx database.Tx) error {
		_, err := w.Keychain.KeyForAddress(tx, addrs[0], nil)
		return err
	})
	if err != ErrEncryptedKeychain {
		t.Errorf("Expected ErrEncryptedKeychain, got %s", err)
	}

	if err := w.RemovePassphrase(pw2); err != nil {
		t.Fatal(err)
	}

	if w.Keychain.IsEncrypted() {
		t.Fatal("Keychain is encrypted")
	}
}

func TestWalletBase_WatchAddress(t *testing.T) {
	w, err := setupWallet()
	if err != nil {
		t.Fatal(err)
	}
	xpriv, err := hd.NewKeyFromString("tprv8ZgxMBicQKsPeghT19pungdFLMJM2hMs3EEn5WtgobD7wuQSFQu4VNaEJXH9HS3RhhLT4wgZ3hj31m3kafuxhL9vfGTRtBVLSog4zjxW3L1")
	if err != nil {
		t.Fatal(err)
	}

	if err := w.CreateWallet(*xpriv, nil, time.Now()); err != nil {
		t.Fatal(err)
	}

	if err := w.OpenWallet(); err != nil {
		t.Fatal(err)
	}
	w.ChainManager.eventBus = NewBus()

	sub, err := w.ChainManager.eventBus.Subscribe(&WatchAddressAddedEvent{})
	if err != nil {
		t.Fatal(err)
	}

	wtx, err := w.Begin()
	if err != nil {
		t.Fatal(err)
	}
	addr := "abc"
	if err := w.WatchAddress(wtx, iwallet.NewAddress(addr, iwallet.CtMock)); err != nil {
		t.Fatal(err)
	}

	if err := wtx.Commit(); err != nil {
		t.Fatal(err)
	}

	select {
	case <-sub.Out():
	case <-time.After(time.Second * 10):
		t.Fatal("timed out waiting on event")
	}

	if len(w.ChainManager.watchOnly) != 1 {
		t.Errorf("Expected 1 watch only got %d", len(w.ChainManager.watchOnly))
	}

	var watchedAddrs []database.WatchedAddressRecord
	err = w.DB.View(func(tx database.Tx) error {
		return tx.Read().Find(&watchedAddrs).Error
	})
	if err != nil {
		t.Fatal(err)
	}

	if len(watchedAddrs) != 1 {
		t.Errorf("Expected 1 watch only got %d", len(watchedAddrs))
	}

	if watchedAddrs[0].Addr != addr {
		t.Errorf("Expected address %s, got %s", addr, watchedAddrs[0].Addr)
	}
}

func TestWalletBase_GetAddressTransactions(t *testing.T) {
	w, err := setupWallet()
	if err != nil {
		t.Fatal(err)
	}
	addr := iwallet.NewAddress("abc", iwallet.CtMock)
	if err := w.ChainClient.(*MockChainClient).BroadcastInternal(NewMockTransaction(nil, &addr)); err != nil {
		t.Fatal(err)
	}

	txs, err := w.GetAddressTransactions(addr)
	if err != nil {
		t.Fatal(err)
	}
	if len(txs) != 1 {
		t.Errorf("Expected 1 transaction got %d", len(txs))
	}
}

func TestWalletBase_GetTransaction(t *testing.T) {
	w, err := setupWallet()
	if err != nil {
		t.Fatal(err)
	}
	addr := iwallet.NewAddress("abc", iwallet.CtMock)
	if err := w.ChainClient.(*MockChainClient).BroadcastInternal(NewMockTransaction(nil, &addr)); err != nil {
		t.Fatal(err)
	}

	txs, err := w.GetAddressTransactions(addr)
	if err != nil {
		t.Fatal(err)
	}
	if len(txs) != 1 {
		t.Errorf("Expected 1 transaction got %d", len(txs))
	}

	tx, err := w.GetTransaction(txs[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if tx.ID != txs[0].ID {
		t.Errorf("Expected txid %s, got %s", txs[0].ID, tx.ID)
	}

	tx2 := NewMockTransaction(nil, nil)
	txr, err := database.NewTransactionRecord(tx2, iwallet.CtMock)
	if err != nil {
		t.Fatal(err)
	}

	err = w.DB.Update(func(tx database.Tx) error {
		return tx.Save(txr)
	})
	if err != nil {
		t.Fatal(err)
	}

	tx, err = w.GetTransaction(tx2.ID)
	if err != nil {
		t.Fatal(err)
	}
	if tx.ID != tx2.ID {
		t.Errorf("Expected txid %s, got %s", tx2.ID, tx.ID)
	}
}

func TestWalletBase_Transactions(t *testing.T) {
	w, err := setupWallet()
	if err != nil {
		t.Fatal(err)
	}

	err = w.DB.Update(func(tx database.Tx) error {
		for i := 0; i < 3; i++ {
			txr, err := database.NewTransactionRecord(NewMockTransaction(nil, nil), iwallet.CtMock)
			if err != nil {
				return err
			}
			txr.Timestamp = time.Now().Add(time.Hour * time.Duration(i))
			if err := tx.Save(txr); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	txs, err := w.Transactions(-1, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(txs) != 3 {
		t.Errorf("Expected 3 txs got %d", len(txs))
	}

	txs2, err := w.Transactions(2, "")
	if err != nil {
		t.Fatal(err)
	}

	if len(txs2) != 2 {
		t.Errorf("Expected 2 txs got %d", len(txs2))
	}

	txs3, err := w.Transactions(-1, txs[1].ID)
	if err != nil {
		t.Fatal(err)
	}

	if len(txs3) != 1 {
		t.Errorf("Expected 1 txs got %d", len(txs3))
	}

	if txs3[0].ID.String() != txs[2].ID.String() {
		t.Errorf("Expected txid %s got %s", txs[2].ID.String(), txs3[0].ID.String())
	}
}

func TestWalletBase_Balance(t *testing.T) {
	w, err := setupWallet()
	if err != nil {
		t.Fatal(err)
	}

	xpriv, err := hd.NewKeyFromString("tprv8ZgxMBicQKsPeghT19pungdFLMJM2hMs3EEn5WtgobD7wuQSFQu4VNaEJXH9HS3RhhLT4wgZ3hj31m3kafuxhL9vfGTRtBVLSog4zjxW3L1")
	if err != nil {
		t.Fatal(err)
	}

	if err := w.CreateWallet(*xpriv, nil, time.Now()); err != nil {
		t.Fatal(err)
	}

	if err := w.OpenWallet(); err != nil {
		t.Fatal(err)
	}

	addr, err := w.CurrentAddress()
	if err != nil {
		t.Fatal(err)
	}

	// Confirmed utxo
	tx0 := NewMockTransaction(nil, &addr)
	tx0.Height = 100000
	tx0.To[0].Amount = iwallet.NewAmount(500)

	// Confirmed utxo
	tx1 := NewMockTransaction(nil, &addr)
	tx1.Height = 100000
	tx1.To[0].Amount = iwallet.NewAmount(700)

	// Unconfirmed utxo
	tx2 := NewMockTransaction(nil, &addr)
	tx2.Height = 0
	tx2.To[0].Amount = iwallet.NewAmount(300)

	// Unconfirmed utxo spending from confirmed
	tx3 := NewMockTransaction(nil, &addr)
	tx3.Height = 100000

	prev, err := hex.DecodeString(tx3.ID.String())
	if err != nil {
		t.Fatal(err)
	}
	tx4 := NewMockTransaction(&iwallet.SpendInfo{
		ID: append(prev, []byte{0x00, 0x00, 0x00, 0x00}...),
	}, &addr)
	tx4.Height = 0
	tx4.To[0].Amount = iwallet.NewAmount(1200)

	err = w.DB.Update(func(dbtx database.Tx) error {
		for _, tx := range []iwallet.Transaction{tx0, tx1, tx2, tx3, tx4} {
			txr, err := database.NewTransactionRecord(tx, iwallet.CtMock)
			if err != nil {
				t.Fatal(err)
			}
			if err := dbtx.Save(txr); err != nil {
				t.Fatal(err)
			}
		}
		for _, tx := range []iwallet.Transaction{tx0, tx1, tx2, tx4} {
			id, err := hex.DecodeString(tx.ID.String())
			if err != nil {
				return err
			}
			utxo := database.UtxoRecord{
				Coin:     iwallet.CtMock,
				Amount:   tx.To[0].Amount.String(),
				Address:  tx.To[0].Address.String(),
				Height:   tx.Height,
				Outpoint: hex.EncodeToString(append(id, []byte{0x00, 0x00, 0x00, 0x00}...)),
			}
			if err := dbtx.Save(&utxo); err != nil {
				t.Fatal(err)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	unconf, conf, err := w.Balance()
	if err != nil {
		t.Fatal(err)
	}
	if conf.Cmp(iwallet.NewAmount(2400)) != 0 {
		t.Errorf("Expected confirmed amount 2400, got %s", conf)
	}
	if unconf.Cmp(iwallet.NewAmount(300)) != 0 {
		t.Errorf("Expected unconfirmed amount 300, got %s", unconf)
	}
}

func TestWalletBase_GatherCoins(t *testing.T) {
	w, err := setupWallet()
	if err != nil {
		t.Fatal(err)
	}

	xpriv, err := hd.NewKeyFromString("tprv8ZgxMBicQKsPeghT19pungdFLMJM2hMs3EEn5WtgobD7wuQSFQu4VNaEJXH9HS3RhhLT4wgZ3hj31m3kafuxhL9vfGTRtBVLSog4zjxW3L1")
	if err != nil {
		t.Fatal(err)
	}

	if err := w.CreateWallet(*xpriv, nil, time.Now()); err != nil {
		t.Fatal(err)
	}

	if err := w.OpenWallet(); err != nil {
		t.Fatal(err)
	}
	<-time.After(time.Second)

	w.ChainClient.(*MockChainClient).GenerateBlock()

	w.ChainManager.eventBus = NewBus()

	sub, err := w.ChainManager.eventBus.Subscribe(&BlockReceivedEvent{})
	if err != nil {
		t.Fatal(err)
	}

	select {
	case <-sub.Out():
	case <-time.After(time.Second * 10):
		t.Fatal("timed out waiting on channel")
	}

	addr, err := w.CurrentAddress()
	if err != nil {
		t.Fatal(err)
	}

	// Confirmed utxo
	tx0 := NewMockTransaction(nil, &addr)
	tx0.Height = 100000
	tx0.To[0].Amount = iwallet.NewAmount(500)

	// Confirmed utxo
	tx1 := NewMockTransaction(nil, &addr)
	tx1.Height = 100000
	tx1.To[0].Amount = iwallet.NewAmount(700)

	// Unconfirmed utxo
	tx2 := NewMockTransaction(nil, &addr)
	tx2.Height = 0
	tx2.To[0].Amount = iwallet.NewAmount(300)

	err = w.DB.Update(func(dbtx database.Tx) error {
		for _, tx := range []iwallet.Transaction{tx0, tx1, tx2} {
			id, err := hex.DecodeString(tx.ID.String())
			if err != nil {
				return err
			}
			utxo := database.UtxoRecord{
				Coin:     iwallet.CtMock,
				Amount:   tx.To[0].Amount.String(),
				Address:  tx.To[0].Address.String(),
				Height:   tx.Height,
				Outpoint: hex.EncodeToString(append(id, []byte{0x00, 0x00, 0x00, 0x00}...)),
			}
			if err := dbtx.Save(&utxo); err != nil {
				t.Fatal(err)
			}
		}

		coinMap, err := w.GatherCoins(dbtx)
		if err != nil {
			t.Fatal(err)
		}
		if len(coinMap) != 3 {
			t.Errorf("Expected %d coins, got %d", 3, len(coinMap))
		}

		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

}
