package bitcoincash

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"github.com/btcsuite/btcutil/hdkeychain"
	"github.com/cpacia/multiwallet/base"
	"github.com/cpacia/multiwallet/database"
	"github.com/cpacia/multiwallet/database/sqlitedb"
	iwallet "github.com/cpacia/wallet-interface"
	"github.com/gcash/bchd/chaincfg"
	"github.com/gcash/bchd/chaincfg/chainhash"
	"github.com/gcash/bchd/txscript"
	"github.com/gcash/bchd/wire"
	"github.com/gcash/bchutil"
	"github.com/op/go-logging"
	"testing"
	"time"
)

func newTestWallet() (*BitcoinCashWallet, error) {
	w := &BitcoinCashWallet{
		testnet: true,
	}

	chainClient := base.NewMockChainClient()

	db, err := sqlitedb.NewMemoryDB()
	if err != nil {
		return nil, err
	}
	if err := database.InitializeDatabase(db); err != nil {
		return nil, err
	}

	w.ChainClient = chainClient
	w.DB = db
	w.Logger = logging.MustGetLogger("bchtest")
	w.CoinType = iwallet.CtBitcoinCash
	w.Done = make(chan struct{})
	w.AddressFunc = w.keyToAddress

	key, err := hdkeychain.NewKeyFromString("tprv8ZgxMBicQKsPeghT19pungdFLMJM2hMs3EEn5WtgobD7wuQSFQu4VNaEJXH9HS3RhhLT4wgZ3hj31m3kafuxhL9vfGTRtBVLSog4zjxW3L1")
	if err != nil {
		return nil, err
	}

	if err := w.CreateWallet(*key, nil, time.Now()); err != nil {
		return nil, err
	}

	if err := w.OpenWallet(); err != nil {
		return nil, err
	}
	return w, nil
}

func TestBitcoinCashWallet_ValidateAddress(t *testing.T) {
	tests := []struct {
		address iwallet.Address
		valid   bool
	}{
		{
			address: iwallet.NewAddress("abc", iwallet.CtBitcoinCash),
			valid:   false,
		},
		{
			address: iwallet.NewAddress("qrk0e04s67l9mf20jvae6fznht04rej57sf8jz2nua", iwallet.CtBitcoinCash),
			valid:   true,
		},
	}
	w, err := newTestWallet()
	if err != nil {
		t.Fatal(err)
	}
	for i, test := range tests {
		err := w.ValidateAddress(test.address)
		if !test.valid && err == nil {
			t.Errorf("Test %d expected invalid address got valid", i)
		}
		if test.valid && err != nil {
			t.Errorf("Test %d expected valid address got invalid", i)
		}
	}
}

func TestBitcoinCashWallet_IsDust(t *testing.T) {
	tests := []struct {
		amount iwallet.Amount
		isDust bool
	}{
		{
			amount: iwallet.NewAmount(0),
			isDust: true,
		},
		{
			amount: iwallet.NewAmount(545),
			isDust: true,
		},
		{
			amount: iwallet.NewAmount(546),
			isDust: false,
		},
	}
	w, err := newTestWallet()
	if err != nil {
		t.Fatal(err)
	}
	for i, test := range tests {
		isDust := w.IsDust(test.amount)
		if test.isDust != isDust {
			t.Errorf("Test %d expected %t got %t", i, test.isDust, isDust)
		}
	}
}

func TestBitcoinCashWallet_buildTx(t *testing.T) {
	w, err := newTestWallet()
	if err != nil {
		t.Fatal(err)
	}

	addr, err := w.Keychain.CurrentAddress(false)
	if err != nil {
		t.Fatal(err)
	}

	fromAddr, err := bchutil.DecodeAddress(addr.String(), &chaincfg.TestNet3Params)
	if err != nil {
		t.Fatal(err)
	}

	fromScript, err := txscript.PayToAddrScript(fromAddr)
	if err != nil {
		t.Fatal(err)
	}

	b := make([]byte, 32)
	rand.Read(b)

	h, err := chainhash.NewHash(b)
	if err != nil {
		t.Fatal(err)
	}

	op := wire.NewOutPoint(h, 0)

	var buf bytes.Buffer
	if err := op.Serialize(&buf); err != nil {
		t.Fatal(err)
	}

	err = w.DB.Update(func(tx database.Tx) error {
		return tx.Save(&database.UtxoRecord{
			Timestamp: time.Now(),
			Amount:    "1000000",
			Height:    600000,
			Coin:      iwallet.CtBitcoinCash,
			Address:   addr.String(),
			Outpoint:  hex.EncodeToString(buf.Bytes()),
		})
	})
	if err != nil {
		t.Fatal(err)
	}

	b = make([]byte, 20)
	rand.Read(b)

	payTo, err := bchutil.NewAddressPubKeyHash(b, &chaincfg.TestNet3Params)
	if err != nil {
		t.Fatal(err)
	}

	var (
		tx     *wire.MsgTx
		outVal = int64(500000)
	)
	err = w.DB.View(func(dbtx database.Tx) error {
		tx, err = w.buildTx(dbtx, outVal, iwallet.NewAddress(payTo.String(), iwallet.CtBitcoinCash), iwallet.FlNormal)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(tx.TxIn) != 1 {
		t.Errorf("Expected 1 input got %d", len(tx.TxIn))
	}
	if tx.TxIn[0].PreviousOutPoint.String() != op.String() {
		t.Errorf("Incorrect input. Expected %s, got %s", op, tx.TxIn[0].PreviousOutPoint.String())
	}
	if len(tx.TxOut) != 2 {
		t.Errorf("Expected 2 outputs got %d", len(tx.TxOut))
	}
	paysTo := false
	script, err := txscript.PayToAddrScript(payTo)
	if err != nil {
		t.Fatal(err)
	}
	var totalOut int64
	for _, out := range tx.TxOut {
		totalOut += out.Value
		if bytes.Equal(script, out.PkScript) {
			if out.Value != outVal {
				t.Errorf("Expected out value %d got %d", outVal, out.Value)
			}
			paysTo = true
		}
	}
	if !paysTo {
		t.Error("Pay to address not found in transaction")
	}
	if totalOut != 996595 {
		t.Errorf("Expected totalOut of %d, got %d", 996595, totalOut)
	}

	vm, err := txscript.NewEngine(fromScript, tx, 0, txscript.StandardVerifyFlags, nil, nil, 1000000)
	if err != nil {
		t.Fatal(err)
	}
	if err := vm.Execute(); err != nil {
		t.Errorf("Script verificationf failed: %s", err)
	}
}
