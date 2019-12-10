package bitcoin

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcutil/hdkeychain"
	"github.com/cpacia/multiwallet/base"
	"github.com/cpacia/multiwallet/database"
	"github.com/cpacia/multiwallet/database/sqlitedb"
	iwallet "github.com/cpacia/wallet-interface"
	"github.com/op/go-logging"
	"testing"
	"time"
)

func newTestWallet() (*BitcoinWallet, error) {
	w := &BitcoinWallet{
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
	w.CoinType = iwallet.CtBitcoin
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

func TestBitcoinWallet_ValidateAddress(t *testing.T) {
	tests := []struct {
		address iwallet.Address
		valid   bool
	}{
		{
			address: iwallet.NewAddress("abc", iwallet.CtBitcoin),
			valid:   false,
		},
		{
			address: iwallet.NewAddress("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", iwallet.CtBitcoin),
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

func TestBitcoinWallet_IsDust(t *testing.T) {
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

func TestBitcoinWallet_EstimateSpendFee(t *testing.T) {
	tests := []struct {
		feeLevel      iwallet.FeeLevel
		amount        iwallet.Amount
		expected      iwallet.Amount
		expectedError error
	}{
		{
			amount:   iwallet.NewAmount(500000),
			feeLevel: iwallet.FlEconomic,
			expected: iwallet.NewAmount(360),
		},
		{
			amount:   iwallet.NewAmount(500000),
			feeLevel: iwallet.FlNormal,
			expected: iwallet.NewAmount(720),
		},
		{
			amount:   iwallet.NewAmount(500000),
			feeLevel: iwallet.FlPriority,
			expected: iwallet.NewAmount(1440),
		},
		{
			amount:        iwallet.NewAmount(1000000),
			feeLevel:      iwallet.FlPriority,
			expected:      iwallet.NewAmount(0),
			expectedError: base.ErrInsufficientFunds,
		},
	}

	w, err := newTestWallet()
	if err != nil {
		t.Fatal(err)
	}

	addr, err := w.Keychain.CurrentAddress(false)
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

	err = w.DB.Update(func(tx database.Tx) error {
		return tx.Save(&database.UtxoRecord{
			Timestamp: time.Now(),
			Amount:    "1000000",
			Height:    600000,
			Coin:      iwallet.CtBitcoin,
			Address:   addr.String(),
			Outpoint:  hex.EncodeToString(serializeOutpoint(op)),
		})
	})
	if err != nil {
		t.Fatal(err)
	}

	for i, test := range tests {
		fee, err := w.EstimateSpendFee(test.amount, test.feeLevel)
		if err != test.expectedError {
			t.Errorf("Test %d: error: %s", i, err)
			continue
		}
		if fee.Cmp(test.expected) != 0 {
			t.Errorf("Test %d: expected %s, got %s", i, test.expected, fee)
		}
	}
}

func TestBitcoinWallet_Spend(t *testing.T) {
	w, err := newTestWallet()
	if err != nil {
		t.Fatal(err)
	}

	addr, err := w.Keychain.CurrentAddress(false)
	if err != nil {
		t.Fatal(err)
	}

	fromAddr, err := btcutil.DecodeAddress(addr.String(), &chaincfg.TestNet3Params)
	if err != nil {
		t.Fatal(err)
	}

	fromScript, err := txscript.PayToAddrScript(fromAddr)
	if err != nil {
		t.Fatal(err)
	}

	h, err := chainhash.NewHashFromStr("bdb237bf8c5de6b60ba1e2dcfe364fc24f583e568d1682f851a9d0f11a45c78d")
	if err != nil {
		t.Fatal(err)
	}

	op := wire.NewOutPoint(h, 0)

	err = w.DB.Update(func(tx database.Tx) error {
		return tx.Save(&database.UtxoRecord{
			Timestamp: time.Now(),
			Amount:    "1000000",
			Height:    600000,
			Coin:      iwallet.CtBitcoin,
			Address:   addr.String(),
			Outpoint:  hex.EncodeToString(serializeOutpoint(op)),
		})
	})
	if err != nil {
		t.Fatal(err)
	}

	wtx, err := w.Begin()
	if err != nil {
		t.Fatal(err)
	}

	txid, err := w.Spend(wtx, iwallet.NewAddress("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", iwallet.CtBitcoin), iwallet.NewAmount(500000), iwallet.FlNormal)
	if err != nil {
		t.Fatal(err)
	}

	expected := "d5fb22ec79246b2185555e62dd3475a955aa430107d78f7eb1b654f0051bfac8"
	if txid.String() != expected {
		t.Errorf("Expected txid %s, got %s", expected, txid)
	}

	if err := wtx.Commit(); err != nil {
		t.Fatal(err)
	}

	var txBytes []byte
	err = w.DB.View(func(tx database.Tx) error {
		var txs []database.UnconfirmedTransaction
		if err := tx.Read().Where("coin=?", iwallet.CtBitcoin).Find(&txs).Error; err != nil {
			return err
		}
		if len(txs) != 1 {
			t.Errorf("Expected 1 tx found %d", len(txs))
		}
		if txs[0].Txid != txid.String() {
			t.Errorf("Expected txid %s, got %s", txid, txs[0].Txid)
		}
		txBytes = txs[0].TxBytes
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	var tx wire.MsgTx
	if err := tx.BtcDecode(bytes.NewReader(txBytes), wire.ProtocolVersion, wire.WitnessEncoding); err != nil {
		t.Fatal(err)
	}

	vm, err := txscript.NewEngine(fromScript, &tx, 0, txscript.StandardVerifyFlags, nil, nil, 1000000)
	if err != nil {
		t.Fatal(err)
	}
	if err := vm.Execute(); err != nil {
		t.Errorf("Script verificationf failed: %s", err)
	}
}

func TestBitcoinWallet_SweepWallet(t *testing.T) {
	w, err := newTestWallet()
	if err != nil {
		t.Fatal(err)
	}

	addr, err := w.Keychain.CurrentAddress(false)
	if err != nil {
		t.Fatal(err)
	}

	fromAddr, err := btcutil.DecodeAddress(addr.String(), &chaincfg.TestNet3Params)
	if err != nil {
		t.Fatal(err)
	}

	fromScript, err := txscript.PayToAddrScript(fromAddr)
	if err != nil {
		t.Fatal(err)
	}

	h, err := chainhash.NewHashFromStr("bdb237bf8c5de6b60ba1e2dcfe364fc24f583e568d1682f851a9d0f11a45c78d")
	if err != nil {
		t.Fatal(err)
	}

	op := wire.NewOutPoint(h, 0)

	err = w.DB.Update(func(tx database.Tx) error {
		return tx.Save(&database.UtxoRecord{
			Timestamp: time.Now(),
			Amount:    "1000000",
			Height:    600000,
			Coin:      iwallet.CtBitcoin,
			Address:   addr.String(),
			Outpoint:  hex.EncodeToString(serializeOutpoint(op)),
		})
	})
	if err != nil {
		t.Fatal(err)
	}

	wtx, err := w.Begin()
	if err != nil {
		t.Fatal(err)
	}

	txid, err := w.SweepWallet(wtx, iwallet.NewAddress("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", iwallet.CtBitcoin), iwallet.FlNormal)
	if err != nil {
		t.Fatal(err)
	}

	expected := "607405710a5d004af494cb0a2c92671e33f8865f1267fed77a5a058a100dd864"
	if txid.String() != expected {
		t.Errorf("Expected txid %s, got %s", expected, txid)
	}

	if err := wtx.Commit(); err != nil {
		t.Fatal(err)
	}

	var txBytes []byte
	err = w.DB.View(func(tx database.Tx) error {
		var txs []database.UnconfirmedTransaction
		if err := tx.Read().Where("coin=?", iwallet.CtBitcoin).Find(&txs).Error; err != nil {
			return err
		}
		if len(txs) != 1 {
			t.Errorf("Expected 1 tx found %d", len(txs))
		}
		if txs[0].Txid != txid.String() {
			t.Errorf("Expected txid %s, got %s", txid, txs[0].Txid)
		}
		txBytes = txs[0].TxBytes
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	var tx wire.MsgTx
	if err := tx.BtcDecode(bytes.NewReader(txBytes), wire.ProtocolVersion, wire.WitnessEncoding); err != nil {
		t.Fatal(err)
	}

	vm, err := txscript.NewEngine(fromScript, &tx, 0, txscript.StandardVerifyFlags, nil, nil, 1000000)
	if err != nil {
		t.Fatal(err)
	}
	if err := vm.Execute(); err != nil {
		t.Errorf("Script verificationf failed: %s", err)
	}
}

func TestBitcoinWallet_EstimateEscrowFee(t *testing.T) {
	tests := []struct {
		threshold int
		level     iwallet.FeeLevel
		expected  iwallet.Amount
	}{
		{
			threshold: 1,
			level:     iwallet.FlEconomic,
			expected:  iwallet.NewAmount(915),
		},
		{
			threshold: 1,
			level:     iwallet.FlNormal,
			expected:  iwallet.NewAmount(1830),
		},
		{
			threshold: 1,
			level:     iwallet.FlPriority,
			expected:  iwallet.NewAmount(3660),
		},
		{
			threshold: 2,
			level:     iwallet.FlEconomic,
			expected:  iwallet.NewAmount(1585),
		},
		{
			threshold: 2,
			level:     iwallet.FlNormal,
			expected:  iwallet.NewAmount(3170),
		},
		{
			threshold: 2,
			level:     iwallet.FlPriority,
			expected:  iwallet.NewAmount(6340),
		},
	}

	w, err := newTestWallet()
	if err != nil {
		t.Fatal(err)
	}
	for i, test := range tests {
		fee, err := w.EstimateEscrowFee(test.threshold, test.level)
		if err != nil {
			t.Errorf("Test %d: error %s", i, err)
		}
		if fee.Cmp(test.expected) != 0 {
			t.Errorf("Test %d: expected %s, got %s", i, test.expected, fee)
		}
	}
}

func TestBitcoinWallet_Multisig1of2(t *testing.T) {
	w, err := newTestWallet()
	if err != nil {
		t.Fatal(err)
	}

	key1Bytes, err := hex.DecodeString("84c8a01a81bf562aafafd4a9fccda533b33d6382b984c081a8cb7817bf909c18")
	if err != nil {
		t.Fatal(err)
	}

	key2Bytes, err := hex.DecodeString("c68ab7796c52952a062b4c875c758ae3831448240fb58c152cc58a224d6ad3b8")
	if err != nil {
		t.Fatal(err)
	}

	key1, _ := btcec.PrivKeyFromBytes(btcec.S256(), key1Bytes)
	key2, _ := btcec.PrivKeyFromBytes(btcec.S256(), key2Bytes)

	address, redeemScript, err := w.CreateMultisigAddress([]btcec.PublicKey{*key1.PubKey(), *key2.PubKey()}, 1)
	if err != nil {
		t.Fatal(err)
	}
	expectedAddr := "tb1qv5plgrqexzju9jympkh2qjcalgn0qytp2erqls9xaumc3nkz7v8swcl0jp"
	if address.String() != expectedAddr {
		t.Errorf("Expected address %s, got %s", expectedAddr, address)
	}
	expectedRedeemScript := "5121031f0ab385f3493b1e750f03ba590df5c7895415446d1c8aa60a7effc658ae183b2103c46f902f37e852dc7e8958bb440af7795fb323be6aaa3e99423076dc076315d052ae"
	if hex.EncodeToString(redeemScript) != expectedRedeemScript {
		t.Errorf("Expected redeem script %s, got %s", expectedRedeemScript, hex.EncodeToString(redeemScript))
	}

	h, err := chainhash.NewHashFromStr("bdb237bf8c5de6b60ba1e2dcfe364fc24f583e568d1682f851a9d0f11a45c78d")
	if err != nil {
		t.Fatal(err)
	}

	op := wire.NewOutPoint(h, 0)

	tx := iwallet.Transaction{
		From: []iwallet.SpendInfo{
			{
				ID:     serializeOutpoint(op),
				Amount: iwallet.NewAmount(1000000),
			},
		},
		To: []iwallet.SpendInfo{
			{
				Amount:  iwallet.NewAmount(900000),
				Address: iwallet.NewAddress("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", iwallet.CtBitcoin),
			},
		},
	}

	sig, err := w.SignMultisigTransaction(tx, *key1, redeemScript)
	if err != nil {
		t.Fatal(err)
	}

	wtx, err := w.Begin()
	if err != nil {
		t.Fatal(err)
	}

	txid, err := w.BuildAndSend(wtx, tx, [][]iwallet.EscrowSignature{sig}, redeemScript)
	if err != nil {
		t.Fatal(err)
	}
	expectedTxid := "b12f50c698dfd650bfdea3568e5cd37634e63a10b8de42187ae2aed120c7fb6b"
	if txid.String() != expectedTxid {
		t.Errorf("Expected txid %s, got %s", expectedTxid, txid)
	}

	if err := wtx.Commit(); err != nil {
		t.Fatal(err)
	}

	var txBytes []byte
	err = w.DB.View(func(tx database.Tx) error {
		var txs []database.UnconfirmedTransaction
		if err := tx.Read().Where("coin=?", iwallet.CtBitcoin).Find(&txs).Error; err != nil {
			return err
		}
		if len(txs) != 1 {
			t.Errorf("Expected 1 tx found %d", len(txs))
		}
		if txs[0].Txid != txid.String() {
			t.Errorf("Expected txid %s, got %s", txid, txs[0].Txid)
		}
		txBytes = txs[0].TxBytes
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	witnessProgram := sha256.Sum256(redeemScript)

	scriptAddr, err := btcutil.NewAddressWitnessScriptHash(witnessProgram[:], w.params())
	if err != nil {
		t.Fatal(err)
	}

	fromScript, err := txscript.PayToAddrScript(scriptAddr)
	if err != nil {
		t.Fatal(err)
	}

	var msgTx wire.MsgTx
	if err := msgTx.BtcDecode(bytes.NewReader(txBytes), wire.ProtocolVersion, wire.WitnessEncoding); err != nil {
		t.Fatal(err)
	}

	vm, err := txscript.NewEngine(fromScript, &msgTx, 0, txscript.StandardVerifyFlags, nil, nil, 1000000)
	if err != nil {
		t.Fatal(err)
	}
	if err := vm.Execute(); err != nil {
		t.Errorf("Script verificationf failed: %s", err)
	}
}

func TestBitcoinWallet_Multisig2of3(t *testing.T) {
	w1, err := newTestWallet()
	if err != nil {
		t.Fatal(err)
	}
	w2, err := newTestWallet()
	if err != nil {
		t.Fatal(err)
	}

	key1Bytes, err := hex.DecodeString("84c8a01a81bf562aafafd4a9fccda533b33d6382b984c081a8cb7817bf909c18")
	if err != nil {
		t.Fatal(err)
	}

	key2Bytes, err := hex.DecodeString("c68ab7796c52952a062b4c875c758ae3831448240fb58c152cc58a224d6ad3b8")
	if err != nil {
		t.Fatal(err)
	}

	key3Bytes, err := hex.DecodeString("0404e6967fc6c638564d4c381e299636fd01fdbcaaaa28e540647c928b44d39b")
	if err != nil {
		t.Fatal(err)
	}

	key1, _ := btcec.PrivKeyFromBytes(btcec.S256(), key1Bytes)
	key2, _ := btcec.PrivKeyFromBytes(btcec.S256(), key2Bytes)
	key3, _ := btcec.PrivKeyFromBytes(btcec.S256(), key3Bytes)

	address, redeemScript, err := w1.CreateMultisigAddress([]btcec.PublicKey{*key1.PubKey(), *key2.PubKey(), *key3.PubKey()}, 2)
	if err != nil {
		t.Fatal(err)
	}
	expectedAddr := "tb1q8tz3nc4wsuh07009rykkgeme9p3qf2nevfa8kjysj34dme6cuq0s98uwsq"
	if address.String() != expectedAddr {
		t.Errorf("Expected address %s, got %s", expectedAddr, address)
	}
	expectedRedeemScript := "5221031f0ab385f3493b1e750f03ba590df5c7895415446d1c8aa60a7effc658ae183b2103c46f902f37e852dc7e8958bb440af7795fb323be6aaa3e99423076dc076315d02102567a15f95333dbed4ff2913e58f554d784cf7787650e44d6b7faf30c79e5b67953ae"
	if hex.EncodeToString(redeemScript) != expectedRedeemScript {
		t.Errorf("Expected redeem script %s, got %s", expectedRedeemScript, hex.EncodeToString(redeemScript))
	}

	h, err := chainhash.NewHashFromStr("bdb237bf8c5de6b60ba1e2dcfe364fc24f583e568d1682f851a9d0f11a45c78d")
	if err != nil {
		t.Fatal(err)
	}

	op := wire.NewOutPoint(h, 0)

	tx := iwallet.Transaction{
		From: []iwallet.SpendInfo{
			{
				ID:     serializeOutpoint(op),
				Amount: iwallet.NewAmount(1000000),
			},
		},
		To: []iwallet.SpendInfo{
			{
				Amount:  iwallet.NewAmount(900000),
				Address: iwallet.NewAddress("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", iwallet.CtBitcoin),
			},
		},
	}

	sig1, err := w1.SignMultisigTransaction(tx, *key1, redeemScript)
	if err != nil {
		t.Fatal(err)
	}

	sig2, err := w2.SignMultisigTransaction(tx, *key2, redeemScript)
	if err != nil {
		t.Fatal(err)
	}

	wtx, err := w1.Begin()
	if err != nil {
		t.Fatal(err)
	}

	txid, err := w1.BuildAndSend(wtx, tx, [][]iwallet.EscrowSignature{sig1, sig2}, redeemScript)
	if err != nil {
		t.Fatal(err)
	}
	expectedTxid := "b12f50c698dfd650bfdea3568e5cd37634e63a10b8de42187ae2aed120c7fb6b"
	if txid.String() != expectedTxid {
		t.Errorf("Expected txid %s, got %s", expectedTxid, txid)
	}

	if err := wtx.Commit(); err != nil {
		t.Fatal(err)
	}

	var txBytes []byte
	err = w1.DB.View(func(tx database.Tx) error {
		var txs []database.UnconfirmedTransaction
		if err := tx.Read().Where("coin=?", iwallet.CtBitcoin).Find(&txs).Error; err != nil {
			return err
		}
		if len(txs) != 1 {
			t.Errorf("Expected 1 tx found %d", len(txs))
		}
		if txs[0].Txid != txid.String() {
			t.Errorf("Expected txid %s, got %s", txid, txs[0].Txid)
		}
		txBytes = txs[0].TxBytes
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	witnessProgram := sha256.Sum256(redeemScript)

	scriptAddr, err := btcutil.NewAddressWitnessScriptHash(witnessProgram[:], w1.params())
	if err != nil {
		t.Fatal(err)
	}

	fromScript, err := txscript.PayToAddrScript(scriptAddr)
	if err != nil {
		t.Fatal(err)
	}

	var msgTx wire.MsgTx
	if err := msgTx.BtcDecode(bytes.NewReader(txBytes), wire.ProtocolVersion, wire.WitnessEncoding); err != nil {
		t.Fatal(err)
	}

	vm, err := txscript.NewEngine(fromScript, &msgTx, 0, txscript.StandardVerifyFlags, nil, nil, 1000000)
	if err != nil {
		t.Fatal(err)
	}
	if err := vm.Execute(); err != nil {
		t.Errorf("Script verificationf failed: %s", err)
	}
}

func TestBitcoinWallet_Multisig2of3Timlocked(t *testing.T) {
	w1, err := newTestWallet()
	if err != nil {
		t.Fatal(err)
	}
	w2, err := newTestWallet()
	if err != nil {
		t.Fatal(err)
	}

	key1Bytes, err := hex.DecodeString("84c8a01a81bf562aafafd4a9fccda533b33d6382b984c081a8cb7817bf909c18")
	if err != nil {
		t.Fatal(err)
	}

	key2Bytes, err := hex.DecodeString("c68ab7796c52952a062b4c875c758ae3831448240fb58c152cc58a224d6ad3b8")
	if err != nil {
		t.Fatal(err)
	}

	key3Bytes, err := hex.DecodeString("0404e6967fc6c638564d4c381e299636fd01fdbcaaaa28e540647c928b44d39b")
	if err != nil {
		t.Fatal(err)
	}

	key1, _ := btcec.PrivKeyFromBytes(btcec.S256(), key1Bytes)
	key2, _ := btcec.PrivKeyFromBytes(btcec.S256(), key2Bytes)
	key3, _ := btcec.PrivKeyFromBytes(btcec.S256(), key3Bytes)

	address, redeemScript, err := w1.CreateMultisigWithTimeout([]btcec.PublicKey{*key1.PubKey(), *key2.PubKey(), *key3.PubKey()}, 2, time.Hour*24, *key2.PubKey())
	if err != nil {
		t.Fatal(err)
	}
	expectedAddr := "tb1qxpskrwmxttvynhrckl4da3jweaz50y20j6n9qrpfdtefvhwgvyxqur3559"
	if address.String() != expectedAddr {
		t.Errorf("Expected address %s, got %s", expectedAddr, address)
	}
	expectedRedeemScript := "635221031f0ab385f3493b1e750f03ba590df5c7895415446d1c8aa60a7effc658ae183b2103c46f902f37e852dc7e8958bb440af7795fb323be6aaa3e99423076dc076315d02102567a15f95333dbed4ff2913e58f554d784cf7787650e44d6b7faf30c79e5b67953ae67029000b2752103c46f902f37e852dc7e8958bb440af7795fb323be6aaa3e99423076dc076315d0ac68"
	if hex.EncodeToString(redeemScript) != expectedRedeemScript {
		t.Errorf("Expected redeem script %s, got %s", expectedRedeemScript, hex.EncodeToString(redeemScript))
	}

	h, err := chainhash.NewHashFromStr("bdb237bf8c5de6b60ba1e2dcfe364fc24f583e568d1682f851a9d0f11a45c78d")
	if err != nil {
		t.Fatal(err)
	}

	op := wire.NewOutPoint(h, 0)

	tx := iwallet.Transaction{
		From: []iwallet.SpendInfo{
			{
				ID:     serializeOutpoint(op),
				Amount: iwallet.NewAmount(1000000),
			},
		},
		To: []iwallet.SpendInfo{
			{
				Amount:  iwallet.NewAmount(900000),
				Address: iwallet.NewAddress("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", iwallet.CtBitcoin),
			},
		},
	}

	sig1, err := w1.SignMultisigTransaction(tx, *key1, redeemScript)
	if err != nil {
		t.Fatal(err)
	}

	sig2, err := w2.SignMultisigTransaction(tx, *key2, redeemScript)
	if err != nil {
		t.Fatal(err)
	}

	wtx, err := w1.Begin()
	if err != nil {
		t.Fatal(err)
	}

	txid, err := w1.BuildAndSend(wtx, tx, [][]iwallet.EscrowSignature{sig1, sig2}, redeemScript)
	if err != nil {
		t.Fatal(err)
	}
	expectedTxid := "b12f50c698dfd650bfdea3568e5cd37634e63a10b8de42187ae2aed120c7fb6b"
	if txid.String() != expectedTxid {
		t.Errorf("Expected txid %s, got %s", expectedTxid, txid)
	}

	if err := wtx.Commit(); err != nil {
		t.Fatal(err)
	}

	var txBytes []byte
	err = w1.DB.View(func(tx database.Tx) error {
		var txs []database.UnconfirmedTransaction
		if err := tx.Read().Where("coin=?", iwallet.CtBitcoin).Find(&txs).Error; err != nil {
			return err
		}
		if len(txs) != 1 {
			t.Errorf("Expected 1 tx found %d", len(txs))
		}
		if txs[0].Txid != txid.String() {
			t.Errorf("Expected txid %s, got %s", txid, txs[0].Txid)
		}
		txBytes = txs[0].TxBytes
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	witnessProgram := sha256.Sum256(redeemScript)

	scriptAddr, err := btcutil.NewAddressWitnessScriptHash(witnessProgram[:], w1.params())
	if err != nil {
		t.Fatal(err)
	}

	fromScript, err := txscript.PayToAddrScript(scriptAddr)
	if err != nil {
		t.Fatal(err)
	}

	var msgTx wire.MsgTx
	if err := msgTx.BtcDecode(bytes.NewReader(txBytes), wire.ProtocolVersion, wire.WitnessEncoding); err != nil {
		t.Fatal(err)
	}

	vm, err := txscript.NewEngine(fromScript, &msgTx, 0, txscript.StandardVerifyFlags, nil, nil, 1000000)
	if err != nil {
		t.Fatal(err)
	}
	if err := vm.Execute(); err != nil {
		t.Errorf("Script verificationf failed: %s", err)
	}
}

func TestBitcoinWallet_ReleaseFundsAfterTimeout(t *testing.T) {
	w, err := newTestWallet()
	if err != nil {
		t.Fatal(err)
	}

	key1Bytes, err := hex.DecodeString("84c8a01a81bf562aafafd4a9fccda533b33d6382b984c081a8cb7817bf909c18")
	if err != nil {
		t.Fatal(err)
	}

	key2Bytes, err := hex.DecodeString("c68ab7796c52952a062b4c875c758ae3831448240fb58c152cc58a224d6ad3b8")
	if err != nil {
		t.Fatal(err)
	}

	key3Bytes, err := hex.DecodeString("0404e6967fc6c638564d4c381e299636fd01fdbcaaaa28e540647c928b44d39b")
	if err != nil {
		t.Fatal(err)
	}

	key1, _ := btcec.PrivKeyFromBytes(btcec.S256(), key1Bytes)
	key2, _ := btcec.PrivKeyFromBytes(btcec.S256(), key2Bytes)
	key3, _ := btcec.PrivKeyFromBytes(btcec.S256(), key3Bytes)

	address, redeemScript, err := w.CreateMultisigWithTimeout([]btcec.PublicKey{*key1.PubKey(), *key2.PubKey(), *key3.PubKey()}, 2, time.Hour*24, *key2.PubKey())
	if err != nil {
		t.Fatal(err)
	}
	expectedAddr := "tb1qxpskrwmxttvynhrckl4da3jweaz50y20j6n9qrpfdtefvhwgvyxqur3559"
	if address.String() != expectedAddr {
		t.Errorf("Expected address %s, got %s", expectedAddr, address)
	}
	expectedRedeemScript := "635221031f0ab385f3493b1e750f03ba590df5c7895415446d1c8aa60a7effc658ae183b2103c46f902f37e852dc7e8958bb440af7795fb323be6aaa3e99423076dc076315d02102567a15f95333dbed4ff2913e58f554d784cf7787650e44d6b7faf30c79e5b67953ae67029000b2752103c46f902f37e852dc7e8958bb440af7795fb323be6aaa3e99423076dc076315d0ac68"
	if hex.EncodeToString(redeemScript) != expectedRedeemScript {
		t.Errorf("Expected redeem script %s, got %s", expectedRedeemScript, hex.EncodeToString(redeemScript))
	}

	h, err := chainhash.NewHashFromStr("bdb237bf8c5de6b60ba1e2dcfe364fc24f583e568d1682f851a9d0f11a45c78d")
	if err != nil {
		t.Fatal(err)
	}

	op := wire.NewOutPoint(h, 0)

	tx := iwallet.Transaction{
		From: []iwallet.SpendInfo{
			{
				ID:     serializeOutpoint(op),
				Amount: iwallet.NewAmount(1000000),
			},
		},
		To: []iwallet.SpendInfo{
			{
				Amount:  iwallet.NewAmount(900000),
				Address: iwallet.NewAddress("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", iwallet.CtBitcoin),
			},
		},
	}

	wtx, err := w.Begin()
	if err != nil {
		t.Fatal(err)
	}

	txid, err := w.ReleaseFundsAfterTimeout(wtx, tx, *key2, redeemScript)
	if err != nil {
		t.Fatal(err)
	}
	expectedTxid := "3bbcb72cb4c5ff7d6f2c11ef26c64f48f944943300f27b74d064bacf5f3a9369"
	if txid.String() != expectedTxid {
		t.Errorf("Expected txid %s, got %s", expectedTxid, txid)
	}

	if err := wtx.Commit(); err != nil {
		t.Fatal(err)
	}

	var txBytes []byte
	err = w.DB.View(func(tx database.Tx) error {
		var txs []database.UnconfirmedTransaction
		if err := tx.Read().Where("coin=?", iwallet.CtBitcoin).Find(&txs).Error; err != nil {
			return err
		}
		if len(txs) != 1 {
			t.Errorf("Expected 1 tx found %d", len(txs))
		}
		if txs[0].Txid != txid.String() {
			t.Errorf("Expected txid %s, got %s", txid, txs[0].Txid)
		}
		txBytes = txs[0].TxBytes
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	witnessProgram := sha256.Sum256(redeemScript)

	scriptAddr, err := btcutil.NewAddressWitnessScriptHash(witnessProgram[:], w.params())
	if err != nil {
		t.Fatal(err)
	}

	fromScript, err := txscript.PayToAddrScript(scriptAddr)
	if err != nil {
		t.Fatal(err)
	}

	var msgTx wire.MsgTx
	if err := msgTx.BtcDecode(bytes.NewReader(txBytes), wire.ProtocolVersion, wire.WitnessEncoding); err != nil {
		t.Fatal(err)
	}

	vm, err := txscript.NewEngine(fromScript, &msgTx, 0, txscript.StandardVerifyFlags, nil, nil, 1000000)
	if err != nil {
		t.Fatal(err)
	}
	if err := vm.Execute(); err != nil {
		t.Errorf("Script verificationf failed: %s", err)
	}
}

func TestBitcoinWallet_buildTx(t *testing.T) {
	w, err := newTestWallet()
	if err != nil {
		t.Fatal(err)
	}

	addr, err := w.Keychain.CurrentAddress(false)
	if err != nil {
		t.Fatal(err)
	}

	fromAddr, err := btcutil.DecodeAddress(addr.String(), &chaincfg.TestNet3Params)
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

	err = w.DB.Update(func(tx database.Tx) error {
		return tx.Save(&database.UtxoRecord{
			Timestamp: time.Now(),
			Amount:    "1000000",
			Height:    600000,
			Coin:      iwallet.CtBitcoin,
			Address:   addr.String(),
			Outpoint:  hex.EncodeToString(serializeOutpoint(op)),
		})
	})
	if err != nil {
		t.Fatal(err)
	}

	b = make([]byte, 20)
	rand.Read(b)

	payTo, err := btcutil.NewAddressPubKeyHash(b, &chaincfg.TestNet3Params)
	if err != nil {
		t.Fatal(err)
	}

	var (
		tx     *wire.MsgTx
		outVal = int64(500000)
	)
	err = w.DB.View(func(dbtx database.Tx) error {
		tx, err = w.buildTx(dbtx, outVal, iwallet.NewAddress(payTo.String(), iwallet.CtBitcoin), iwallet.FlNormal)
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
	if totalOut != 999250 {
		t.Errorf("Expected totalOut of %d, got %d", 999250, totalOut)
	}

	vm, err := txscript.NewEngine(fromScript, tx, 0, txscript.StandardVerifyFlags, nil, nil, 1000000)
	if err != nil {
		t.Fatal(err)
	}
	if err := vm.Execute(); err != nil {
		t.Errorf("Script verificationf failed: %s", err)
	}
}
