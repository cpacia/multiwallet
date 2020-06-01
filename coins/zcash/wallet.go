package zcash

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	btc "github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcutil/coinset"
	"github.com/btcsuite/btcutil/hdkeychain"
	"github.com/btcsuite/btcutil/txsort"
	"github.com/btcsuite/btcwallet/wallet/txauthor"
	"github.com/btcsuite/btcwallet/wallet/txrules"
	"github.com/btcsuite/btcwallet/wallet/txsizes"
	"github.com/cpacia/multiwallet/base"
	"github.com/cpacia/multiwallet/client/blockbook"
	"github.com/cpacia/multiwallet/database"
	iwallet "github.com/cpacia/wallet-interface"
	mbwire "github.com/martinboehm/btcd/wire"
	"github.com/martinboehm/btcutil"
	"github.com/martinboehm/btcutil/chaincfg"
	"github.com/martinboehm/btcutil/txscript"
	"github.com/minio/blake2b-simd"
	"time"
)

var (
	txHeaderBytes          = []byte{0x04, 0x00, 0x00, 0x80}
	txNVersionGroupIDBytes = []byte{0x85, 0x20, 0x2f, 0x89}

	hashPrevOutPersonalization  = []byte("ZcashPrevoutHash")
	hashSequencePersonalization = []byte("ZcashSequencHash")
	hashOutputsPersonalization  = []byte("ZcashOutputsHash")
	sigHashPersonalization      = []byte("ZcashSigHash")

	// MainNetParams are parser parameters for mainnet
	MainNetParams chaincfg.Params
	// TestNetParams are parser parameters for testnet
	TestNetParams chaincfg.Params
)

const (
	sigHashMask     = 0x1f
	blossomBranchID = 0x2BB40E60

	// MainnetMagic is mainnet network constant
	MainnetMagic mbwire.BitcoinNet = 0x6427e924
	// TestnetMagic is testnet network constant
	TestnetMagic mbwire.BitcoinNet = 0xbff91afa

	divisibility           = 8
	averageTransactionSize = 226
	maxFeePerByte          = 200
	priorityTarget         = 10
	normalTarget           = 3
	economicTarget         = 1
	superEconomicTarget    = 0.2
)

// Assert interfaces
var _ = iwallet.Wallet(&ZCashWallet{})
var _ = iwallet.WalletCrypter(&ZCashWallet{})
var _ = iwallet.Escrow(&ZCashWallet{})

func init() {
	MainNetParams = chaincfg.MainNetParams
	MainNetParams.Net = MainnetMagic

	// Address encoding magics
	MainNetParams.AddressMagicLen = 2
	MainNetParams.PubKeyHashAddrID = []byte{0x1C, 0xB8} // base58 prefix: t1
	MainNetParams.ScriptHashAddrID = []byte{0x1C, 0xBD} // base58 prefix: t3

	TestNetParams = chaincfg.TestNet3Params
	TestNetParams.Net = TestnetMagic

	// Address encoding magics
	TestNetParams.AddressMagicLen = 2
	TestNetParams.PubKeyHashAddrID = []byte{0x1D, 0x25} // base58 prefix: tm
	TestNetParams.ScriptHashAddrID = []byte{0x1C, 0xBA} // base58 prefix: t2
}

// ZCashWallet extends wallet base and implements the
// remaining functions for each interface.
type ZCashWallet struct {
	base.WalletBase
	testnet     bool
	feeUrl      string
	feeProvider base.FeeProvider
}

// NewZCashWallet returns a new ZCashWallet. This constructor
// attempts to connect to the API. If it fails, it will not build.
func NewZCashWallet(cfg *base.WalletConfig) (*ZCashWallet, error) {
	w := &ZCashWallet{
		testnet: cfg.Testnet,
		feeUrl:  cfg.FeeUrl,
	}

	chainClient, err := blockbook.NewBlockbookClient(cfg.ClientUrl, iwallet.CtZCash)
	if err != nil {
		return nil, err
	}

	fp := base.NewExchangeRateFeeProvider(iwallet.CtZCash, divisibility, cfg.ExchangeRateProvider, averageTransactionSize,
		iwallet.NewAmount(maxFeePerByte), priorityTarget, normalTarget, economicTarget, superEconomicTarget)

	w.ChainClient = chainClient
	w.DB = cfg.DB
	w.Logger = cfg.Logger
	w.CoinType = iwallet.CtZCash
	w.Done = make(chan struct{})
	w.AddressFunc = w.keyToAddress
	w.feeProvider = fp
	return w, nil
}

// ValidateAddress validates that the serialization of the address is correct
// for this coin and network. It returns an error if it isn't.
func (w *ZCashWallet) ValidateAddress(addr iwallet.Address) error {
	_, err := btcutil.DecodeAddress(addr.String(), w.params())
	return err
}

// IsDust returns whether the amount passed in is considered dust by network. This
// method is called when building payout transactions from the multisig to the various
// participants. If the amount that is supposed to be sent to a given party is below
// the dust threshold, openbazaar-go will not pay that party to avoid building a transaction
// that never confirms.
func (w *ZCashWallet) IsDust(amount iwallet.Amount) bool {
	return txrules.IsDustAmount(btc.Amount(amount.Int64()), 25, txrules.DefaultRelayFeePerKb)
}

// EstimateSpendFee should return the anticipated fee to transfer a given amount of coins
// out of the wallet at the provided fee level. Typically this involves building a
// transaction with enough inputs to cover the request amount and calculating the size
// of the transaction. It is OK, if a transaction comes in after this function is called
// that changes the estimated fee as it's only intended to be an estimate.
//
// All amounts should be in the coin's base unit (for example: satoshis).
func (w *ZCashWallet) EstimateSpendFee(amount iwallet.Amount, feeLevel iwallet.FeeLevel) (iwallet.Amount, error) {
	amt := iwallet.NewAmount(0)
	err := w.DB.Update(func(dbtx database.Tx) error {
		// Since this is an estimate we can use a dummy output address. Let's use a long one so we don't under estimate.
		addrStr := "t1SV7MDC2gCsvySErQC9Pmaz69HorFLmqD9"
		if w.testnet {
			addrStr = "tmJKrg3gS4sPS7gSJ4vT8dFeqkGtfnDW4gu"
		}
		tx, err := w.buildTx(dbtx, amount.Int64(), iwallet.NewAddress(addrStr, iwallet.CtZCash), feeLevel)
		if err != nil {
			return err
		}
		var outval int64
		for _, output := range tx.TxOut {
			outval += output.Value
		}
		var utxoRecords []database.UtxoRecord
		err = dbtx.Read().Where("coin = ?", w.CoinType.CurrencyCode()).Find(&utxoRecords).Error
		if err != nil {
			return err
		}

		var inval int64
		for _, input := range tx.TxIn {
			for _, utxo := range utxoRecords {
				ser, err := hex.DecodeString(utxo.Outpoint)
				if err != nil {
					return err
				}
				op, err := derializeOutpoint(ser)
				if err != nil {
					return err
				}

				if op.Hash.IsEqual(&input.PreviousOutPoint.Hash) && op.Index == input.PreviousOutPoint.Index {
					inval += iwallet.NewAmount(utxo.Amount).Int64()
					break
				}
			}
		}
		if inval < outval {
			return errors.New("error building transaction: inputs less than outputs")
		}
		amt = iwallet.NewAmount(inval - outval)
		return nil
	})
	return amt, err
}

// Spend is a request to send requested amount to the requested address. The
// fee level is provided by the user. It's up to the implementation to decide
// how best to use the fee level.
//
// The database Tx MUST be respected. When this function is called the wallet
// state changes should be prepped and held in memory. If Rollback() is called
// the state changes should be discarded. Only when Commit() is called should
// the state changes be applied and the transaction broadcasted to the network.
func (w *ZCashWallet) Spend(wtx iwallet.Tx, to iwallet.Address, amt iwallet.Amount, feeLevel iwallet.FeeLevel) (iwallet.TransactionID, error) {
	var (
		txid iwallet.TransactionID
		buf  []byte
	)
	err := w.DB.View(func(dbtx database.Tx) error {
		tx, err := w.buildTx(dbtx, amt.Int64(), to, feeLevel)
		if err != nil {
			return err
		}
		txid = iwallet.TransactionID(tx.TxHash().String())
		buf, err = serializeVersion4Transaction(tx, 0)
		if err != nil {
			return err
		}
		return nil
	})

	wbtx, ok := wtx.(*base.DBTx)
	if !ok {
		return txid, errors.New("tx is not expected type")
	}

	wbtx.OnCommit = func() error {
		return w.DB.Update(func(dbtx database.Tx) error {
			err := dbtx.Save(&database.UnconfirmedTransaction{
				Timestamp: time.Now(),
				Coin:      iwallet.CtZCash,
				TxBytes:   buf,
				Txid:      txid.String(),
			})
			if err != nil {
				return err
			}
			return w.ChainClient.Broadcast(buf)
		})
	}
	return txid, err
}

// SweepWallet should sweep the full balance of the wallet to the requested
// address. It is expected for most coins that the fee will be subtracted
// from the amount sent rather than added to it.
func (w *ZCashWallet) SweepWallet(wtx iwallet.Tx, to iwallet.Address, level iwallet.FeeLevel) (iwallet.TransactionID, error) {
	var (
		txid iwallet.TransactionID
		buf  []byte
	)
	err := w.DB.Update(func(dbtx database.Tx) error {
		var (
			totalIn               btcutil.Amount
			tx                    = wire.NewMsgTx(1)
			keyMap                = make(map[wire.OutPoint]*btcec.PrivateKey)
			additionalPrevScripts = make(map[wire.OutPoint][]byte)
			inVals                = make(map[wire.OutPoint]int64)
		)

		coinMap, err := w.GatherCoins(dbtx)
		if err != nil {
			return err
		}

		for coin, key := range coinMap {
			h, err := chainhash.NewHashFromStr(coin.Hash().String())
			if err != nil {
				return err
			}
			op := wire.NewOutPoint(h, coin.Index())
			tx.AddTxIn(wire.NewTxIn(op, nil, nil))
			totalIn += btcutil.Amount(coin.Value().ToUnit(btc.AmountSatoshi))

			inVals[*op] = int64(coin.Value())

			priv, err := key.ECPrivKey()
			if err != nil {
				return err
			}
			keyMap[*op] = priv

			address, err := btcutil.DecodeAddress(string(coin.PkScript()), w.params())
			if err != nil {
				return err
			}

			script, err := txscript.PayToAddrScript(address)
			if err != nil {
				return err
			}

			additionalPrevScripts[*op] = script
		}
		addr, err := btcutil.DecodeAddress(to.String(), w.params())
		if err != nil {
			return err
		}

		script, err := txscript.PayToAddrScript(addr)
		if err != nil {
			return err
		}

		tx.AddTxOut(wire.NewTxOut(0, script))

		size := txsizes.EstimateSerializeSize(len(tx.TxIn), tx.TxOut, false)
		fpb, err := w.feeProvider.GetFee(level)
		if err != nil {
			return err
		}
		fee := fpb.Mul(iwallet.NewAmount(size)).Int64()

		tx.TxOut[0].Value = int64(totalIn) - fee

		// BIP 69 sorting
		txsort.InPlaceSort(tx)

		// Sign tx
		blockchainInfo, err := w.BlockchainInfo()
		if err != nil {
			return err
		}

		for i, txIn := range tx.TxIn {
			prevOutScript := additionalPrevScripts[txIn.PreviousOutPoint]
			key := keyMap[txIn.PreviousOutPoint]

			sig, err := rawTxInSignature(tx, i, prevOutScript, txscript.SigHashAll, key, inVals[txIn.PreviousOutPoint], blockchainInfo.Height)
			if err != nil {
				return errors.New("failed to sign transaction")
			}

			builder := txscript.NewScriptBuilder()
			builder.AddData(sig)
			builder.AddData(key.PubKey().SerializeCompressed())
			script, err := builder.Script()
			if err != nil {
				return err
			}
			txIn.SignatureScript = script
		}

		txid = iwallet.TransactionID(tx.TxHash().String())
		buf, err = serializeVersion4Transaction(tx, 0)
		if err != nil {
			return err
		}

		return nil
	})

	wbtx, ok := wtx.(*base.DBTx)
	if !ok {
		return txid, errors.New("tx is not expected type")
	}

	wbtx.OnCommit = func() error {
		return w.DB.Update(func(dbtx database.Tx) error {
			err := dbtx.Save(&database.UnconfirmedTransaction{
				Timestamp: time.Now(),
				Coin:      iwallet.CtZCash,
				TxBytes:   buf,
				Txid:      txid.String(),
			})
			if err != nil {
				return err
			}
			return w.ChainClient.Broadcast(buf)
		})
	}

	return txid, err
}

// EstimateEscrowFee estimates the fee to release the funds from escrow.
// this assumes only one input. If there are more inputs OpenBazaar will
// will add 50% of the returned fee for each additional input. This is a
// crude fee calculating but it simplifies things quite a bit.
func (w *ZCashWallet) EstimateEscrowFee(threshold int, level iwallet.FeeLevel) (iwallet.Amount, error) {
	var (
		nOuts            = 2
		redeemScriptSize = 4 + (threshold+1)*34
	)
	if threshold == 1 {
		nOuts = 1
	}

	// 8 additional bytes are for version and locktime
	// 15 trailing bytes are zcash tx metadata
	size := 8 + wire.VarIntSerializeSize(1) +
		wire.VarIntSerializeSize(uint64(nOuts)) + 1 +
		threshold*66 + txsizes.P2PKHOutputSize*nOuts + redeemScriptSize + 15

	fpb, err := w.feeProvider.GetFee(level)
	if err != nil {
		return iwallet.NewAmount(0), err
	}
	return fpb.Mul(iwallet.NewAmount(size)), nil
}

// CreateMultisigAddress creates a new threshold multisig address using the
// provided pubkeys and the threshold. The multisig address is returned along
// with a byte slice. The byte slice will typically be the redeem script for
// the address (in Bitcoin related coins). The slice will be saved in OpenBazaar
// with the order and passed back into the wallet when signing the transaction.
// In practice this does not need to be a redeem script so long as the wallet
// knows how to sign the transaction when it sees it.
//
// This function should be deterministic as both buyer and vendor will be passing
// in the same set of keys and expecting to get back the same address and redeem
// script. If this is not the case the vendor will reject the order.
//
// Note that this is normally a 2 of 3 escrow in the normal case, however OpenBazaar
// also uses 1 of 2 multisigs as a form of a "cancelable" address when sending to
// a node that is offline. This allows the sender to cancel the payment if the vendor
// never comes back online.
func (w *ZCashWallet) CreateMultisigAddress(keys []btcec.PublicKey, threshold int) (iwallet.Address, []byte, error) {
	if len(keys) < threshold {
		return iwallet.Address{}, nil, fmt.Errorf("unable to generate multisig script with "+
			"%d required signatures when there are only %d public "+
			"keys available", threshold, len(keys))
	}

	if len(keys) > 8 {
		return iwallet.Address{}, nil, fmt.Errorf("unable to generate multisig script with " +
			"more than 8 public keys")
	}

	builder := txscript.NewScriptBuilder()
	builder.AddInt64(int64(threshold))
	for _, key := range keys {
		builder.AddData(key.SerializeCompressed())
	}
	builder.AddInt64(int64(len(keys)))
	builder.AddOp(txscript.OP_CHECKMULTISIG)

	redeemScript, err := builder.Script()
	if err != nil {
		return iwallet.Address{}, nil, err
	}
	addr, err := btcutil.NewAddressScriptHash(redeemScript, w.params())
	if err != nil {
		return iwallet.Address{}, nil, err
	}
	return iwallet.NewAddress(addr.String(), iwallet.CtZCash), redeemScript, nil
}

// SignMultisigTransaction should use the provided key to create a signature for
// the multisig transaction. Since this a threshold signature this function will
// separately by each party signing this transaction. The resulting signatures
// will be shared between the relevant parties and one of them will aggregate
// the signatures into a transaction for broadcast.
//
// For coins like bitcoin you may need to return one signature *per input* which is
// why a slice of signatures is returned.
func (w *ZCashWallet) SignMultisigTransaction(txn iwallet.Transaction, key btcec.PrivateKey, redeemScript []byte) ([]iwallet.EscrowSignature, error) {
	var sigs []iwallet.EscrowSignature
	tx := wire.NewMsgTx(1)
	for _, from := range txn.From {
		op, err := derializeOutpoint(from.ID)
		if err != nil {
			return nil, err
		}

		input := wire.NewTxIn(op, nil, nil)
		tx.TxIn = append(tx.TxIn, input)
	}
	for _, to := range txn.To {
		addr, err := btcutil.DecodeAddress(to.Address.String(), w.params())
		if err != nil {
			return nil, err
		}

		scriptPubkey, err := txscript.PayToAddrScript(addr)
		if err != nil {
			return nil, err
		}
		output := wire.NewTxOut(to.Amount.Int64(), scriptPubkey)
		tx.TxOut = append(tx.TxOut, output)
	}

	// BIP 69 sorting
	txsort.InPlaceSort(tx)

	blockchainInfo, err := w.BlockchainInfo()
	if err != nil {
		return nil, err
	}
	for i := range tx.TxIn {
		sig, err := rawTxInSignature(tx, i, redeemScript, txscript.SigHashAll, &key, txn.From[i].Amount.Int64(), blockchainInfo.Height)
		if err != nil {
			return nil, err
		}
		bs := iwallet.EscrowSignature{Index: i, Signature: sig[:len(sig)-1]}
		sigs = append(sigs, bs)
	}
	return sigs, nil
}

// BuildAndSend should used the passed in signatures to build the transaction.
// Note the signatures are a slice of slices. This is because coins like Bitcoin
// may require one signature *per input*. In this case the outer slice is the
// signatures from the different key holders and the inner slice is the keys
// per input.
//
// Note a database transaction is used here. Same rules of Commit() and
// Rollback() apply.
func (w *ZCashWallet) BuildAndSend(wtx iwallet.Tx, txn iwallet.Transaction, signatures [][]iwallet.EscrowSignature, redeemScript []byte) (iwallet.TransactionID, error) {
	tx := wire.NewMsgTx(1)
	for _, from := range txn.From {
		op, err := derializeOutpoint(from.ID)
		if err != nil {
			return iwallet.TransactionID(""), err
		}
		input := wire.NewTxIn(op, nil, nil)
		tx.TxIn = append(tx.TxIn, input)
	}
	for _, to := range txn.To {
		addr, err := btcutil.DecodeAddress(to.Address.String(), w.params())
		if err != nil {
			return iwallet.TransactionID(""), err
		}

		scriptPubkey, err := txscript.PayToAddrScript(addr)
		if err != nil {
			return iwallet.TransactionID(""), err
		}
		output := wire.NewTxOut(to.Amount.Int64(), scriptPubkey)
		tx.TxOut = append(tx.TxOut, output)
	}

	for _, sig := range signatures {
		if len(sig) != len(tx.TxIn) {
			return iwallet.TransactionID(""), errors.New("incorrect number of signatures")
		}
	}

	// BIP 69 sorting
	txsort.InPlaceSort(tx)

	for i := range tx.TxIn {
		var sigs [][]byte
		for _, escrowSigs := range signatures {
			for _, sig := range escrowSigs {
				if sig.Index == i {
					sigs = append(sigs, append(sig.Signature, byte(txscript.SigHashAll)))
					break
				}
			}
		}

		builder := txscript.NewScriptBuilder()
		builder.AddOp(txscript.OP_0)
		for _, sig := range sigs {
			builder.AddData(sig)
		}

		builder.AddData(redeemScript)
		scriptSig, err := builder.Script()
		if err != nil {
			return iwallet.TransactionID(""), err
		}
		tx.TxIn[i].SignatureScript = scriptSig
	}

	txid := iwallet.TransactionID(tx.TxHash().String())

	buf, err := serializeVersion4Transaction(tx, 0)
	if err != nil {
		return txid, err
	}

	wbtx, ok := wtx.(*base.DBTx)
	if !ok {
		return txid, errors.New("tx is not expected type")
	}

	wbtx.OnCommit = func() error {
		return w.DB.Update(func(dbtx database.Tx) error {
			err := dbtx.Save(&database.UnconfirmedTransaction{
				Timestamp: time.Now(),
				Coin:      iwallet.CtZCash,
				TxBytes:   buf,
				Txid:      tx.TxHash().String(),
			})
			if err != nil {
				return err
			}
			return w.ChainClient.Broadcast(buf)
		})
	}

	return txid, nil
}

func (w *ZCashWallet) params() *chaincfg.Params {
	if w.testnet {
		if !chaincfg.IsRegistered(&TestNetParams) {
			chaincfg.Register(&TestNetParams)
		}
		return &TestNetParams
	} else {
		if !chaincfg.IsRegistered(&MainNetParams) {
			chaincfg.Register(&MainNetParams)
		}
		return &MainNetParams
	}
}

func (w *ZCashWallet) buildTx(dbtx database.Tx, amount int64, iaddr iwallet.Address, feeLevel iwallet.FeeLevel) (*wire.MsgTx, error) {
	// Check for dust
	addr, err := btcutil.DecodeAddress(iaddr.String(), w.params())
	if err != nil {
		return nil, err
	}
	script, err := txscript.PayToAddrScript(addr)
	if err != nil {
		return nil, err
	}
	if txrules.IsDustAmount(btc.Amount(amount), len(script), txrules.DefaultRelayFeePerKb) {
		return nil, errors.New("dust output amount")
	}

	var (
		additionalKeysByScript = make(map[wire.OutPoint]*btcec.PrivateKey)
		additionalPrevScripts  = make(map[wire.OutPoint][]byte)
		inVals                 = make(map[wire.OutPoint]int64)
	)

	// Create input source
	coinKeyMap, err := w.GatherCoins(dbtx)
	if err != nil {
		return nil, err
	}

	allCoins := make([]coinset.Coin, 0, len(coinKeyMap))
	for coin := range coinKeyMap {
		allCoins = append(allCoins, coin)
	}
	inputSource := func(target btc.Amount) (total btc.Amount, inputs []*wire.TxIn, inputValues []btc.Amount, scripts [][]byte, err error) {
		coinSelector := coinset.MaxValueAgeCoinSelector{MaxInputs: 10000, MinChangeAmount: btc.Amount(txrules.DefaultRelayFeePerKb)}
		coins, err := coinSelector.CoinSelect(btc.Amount(target.ToUnit(btc.AmountSatoshi)), allCoins)
		if err != nil {
			err = base.ErrInsufficientFunds
			return
		}
		for _, c := range coins.Coins() {
			total += btc.Amount(c.Value().ToUnit(btc.AmountSatoshi))

			h, herr := chainhash.NewHashFromStr(c.Hash().String())
			if herr != nil {
				err = herr
				return
			}

			outpoint := wire.NewOutPoint(h, c.Index())

			in := wire.NewTxIn(outpoint, nil, nil)
			inputs = append(inputs, in)

			key := coinKeyMap[c]
			hdKey, kerr := hdkeychain.NewKeyFromString(key.String())
			if kerr != nil {
				err = kerr
				return
			}
			privKey, perr := hdKey.ECPrivKey()
			if perr != nil {
				err = perr
				return
			}

			additionalKeysByScript[*outpoint] = privKey

			address, derr := btcutil.DecodeAddress(string(c.PkScript()), w.params())
			if derr != nil {
				err = derr
				return
			}

			script, perr := txscript.PayToAddrScript(address)
			if perr != nil {
				err = perr
				return
			}

			additionalPrevScripts[*outpoint] = script

			sat := c.Value().ToUnit(btc.AmountSatoshi)
			inVals[*outpoint] = int64(sat)
		}
		return total, inputs, inputValues, scripts, nil
	}

	// Get the fee per kilobyte
	fpb, err := w.feeProvider.GetFee(feeLevel)
	if err != nil {
		return nil, err
	}
	feePerKB := fpb.Int64() * 1000

	// outputs
	out := wire.NewTxOut(amount, script)

	// Create change source
	var changeScript []byte
	changeSource := func() ([]byte, error) {
		iaddr, err := w.Keychain.CurrentAddressWithTx(dbtx, true)
		if err != nil {
			return nil, err
		}

		addr, err := btcutil.DecodeAddress(iaddr.String(), w.params())
		if err != nil {
			return nil, err
		}

		changeScript, err = txscript.PayToAddrScript(addr)
		if err != nil {
			return nil, err
		}
		return bytes.Repeat([]byte{0xFF}, 20), nil
	}

	// Build transaction
	authoredTx, err := txauthor.NewUnsignedTransaction([]*wire.TxOut{out}, btc.Amount(feePerKB), inputSource, changeSource)
	if err != nil {
		return nil, err
	}

	// Hack to get around the fact that txauthor requires the use of segwit change scripts.
	for i, out := range authoredTx.Tx.TxOut {
		if bytes.Equal(out.PkScript, bytes.Repeat([]byte{0xFF}, 20)) {
			authoredTx.Tx.TxOut[i].PkScript = changeScript
			break
		}
	}

	// BIP 69 sorting
	txsort.InPlaceSort(authoredTx.Tx)

	// Sign tx
	tx := authoredTx.Tx
	blockchainInfo, err := w.BlockchainInfo()
	if err != nil {
		return nil, err
	}
	for i, txIn := range tx.TxIn {
		prevOutScript := additionalPrevScripts[txIn.PreviousOutPoint]
		key := additionalKeysByScript[txIn.PreviousOutPoint]

		sig, err := rawTxInSignature(tx, i, prevOutScript, txscript.SigHashAll, key, inVals[txIn.PreviousOutPoint], blockchainInfo.Height)
		if err != nil {
			return nil, errors.New("failed to sign transaction")
		}

		builder := txscript.NewScriptBuilder()
		builder.AddData(sig)
		builder.AddData(key.PubKey().SerializeCompressed())
		script, err := builder.Script()
		if err != nil {
			return nil, err
		}
		txIn.SignatureScript = script
	}
	return tx, nil
}

func (w *ZCashWallet) keyToAddress(key *hdkeychain.ExtendedKey) (iwallet.Address, error) {
	newKey, err := hdkeychain.NewKeyFromString(key.String())
	if err != nil {
		return iwallet.Address{}, err
	}

	pubkey, err := newKey.ECPubKey()
	if err != nil {
		return iwallet.Address{}, err
	}

	pubkeyHash := btcutil.Hash160(pubkey.SerializeCompressed())

	addr, err := btcutil.NewAddressPubKeyHash(pubkeyHash, w.params())
	if err != nil {
		return iwallet.Address{}, err
	}
	return iwallet.NewAddress(addr.String(), iwallet.CtZCash), nil
}

func derializeOutpoint(ser []byte) (*wire.OutPoint, error) {
	h, err := chainhash.NewHash(ser[:32])
	if err != nil {
		return nil, err
	}
	return wire.NewOutPoint(h, binary.LittleEndian.Uint32(ser[32:])), nil
}

func serializeOutpoint(op *wire.OutPoint) []byte {
	i := make([]byte, 4)
	binary.LittleEndian.PutUint32(i, op.Index)
	return append(op.Hash[:], i...)
}

// rawTxInSignature returns the serialized ECDSA signature for the input idx of
// the given transaction, with hashType appended to it.
func rawTxInSignature(tx *wire.MsgTx, idx int, prevScriptBytes []byte,
	hashType txscript.SigHashType, key *btcec.PrivateKey, amt int64, currentHeight uint64) ([]byte, error) {

	hash, err := calcSignatureHash(prevScriptBytes, hashType, tx, idx, amt, 0, currentHeight)
	if err != nil {
		return nil, err
	}
	signature, err := key.Sign(hash)
	if err != nil {
		return nil, fmt.Errorf("cannot sign tx input: %s", err)
	}

	return append(signature.Serialize(), byte(hashType)), nil
}

func calcSignatureHash(prevScriptBytes []byte, hashType txscript.SigHashType, tx *wire.MsgTx, idx int, amt int64, expiry uint32, currentHeight uint64) ([]byte, error) {

	// As a sanity check, ensure the passed input index for the transaction
	// is valid.
	if idx > len(tx.TxIn)-1 {
		return nil, fmt.Errorf("idx %d but %d txins", idx, len(tx.TxIn))
	}

	// We'll utilize this buffer throughout to incrementally calculate
	// the signature hash for this transaction.
	var sigHash bytes.Buffer

	// Write header
	_, err := sigHash.Write(txHeaderBytes)
	if err != nil {
		return nil, err
	}

	// Write group ID
	_, err = sigHash.Write(txNVersionGroupIDBytes)
	if err != nil {
		return nil, err
	}

	// Next write out the possibly pre-calculated hashes for the sequence
	// numbers of all inputs, and the hashes of the previous outs for all
	// outputs.
	var zeroHash chainhash.Hash

	// If anyone can pay isn't active, then we can use the cached
	// hashPrevOuts, otherwise we just write zeroes for the prev outs.
	if hashType&txscript.SigHashAnyOneCanPay == 0 {
		sigHash.Write(calcHashPrevOuts(tx))
	} else {
		sigHash.Write(zeroHash[:])
	}

	// If the sighash isn't anyone can pay, single, or none, the use the
	// cached hash sequences, otherwise write all zeroes for the
	// hashSequence.
	if hashType&txscript.SigHashAnyOneCanPay == 0 &&
		hashType&sigHashMask != txscript.SigHashSingle &&
		hashType&sigHashMask != txscript.SigHashNone {
		sigHash.Write(calcHashSequence(tx))
	} else {
		sigHash.Write(zeroHash[:])
	}

	// If the current signature mode isn't single, or none, then we can
	// re-use the pre-generated hashoutputs sighash fragment. Otherwise,
	// we'll serialize and add only the target output index to the signature
	// pre-image.
	if hashType&sigHashMask != txscript.SigHashSingle &&
		hashType&sigHashMask != txscript.SigHashNone {
		sigHash.Write(calcHashOutputs(tx))
	} else if hashType&sigHashMask == txscript.SigHashSingle && idx < len(tx.TxOut) {
		var b bytes.Buffer
		wire.WriteTxOut(&b, 0, 0, tx.TxOut[idx])
		sigHash.Write(chainhash.DoubleHashB(b.Bytes()))
	} else {
		sigHash.Write(zeroHash[:])
	}

	// Write hash JoinSplits
	sigHash.Write(make([]byte, 32))

	// Write hash ShieldedSpends
	sigHash.Write(make([]byte, 32))

	// Write hash ShieldedOutputs
	sigHash.Write(make([]byte, 32))

	// Write out the transaction's locktime, and the sig hash
	// type.
	var bLockTime [4]byte
	binary.LittleEndian.PutUint32(bLockTime[:], tx.LockTime)
	sigHash.Write(bLockTime[:])

	// Write expiry
	var bExpiryTime [4]byte
	binary.LittleEndian.PutUint32(bExpiryTime[:], expiry)
	sigHash.Write(bExpiryTime[:])

	// Write valueblance
	sigHash.Write(make([]byte, 8))

	// Write the hash type
	var bHashType [4]byte
	binary.LittleEndian.PutUint32(bHashType[:], uint32(hashType))
	sigHash.Write(bHashType[:])

	// Next, write the outpoint being spent.
	sigHash.Write(tx.TxIn[idx].PreviousOutPoint.Hash[:])
	var bIndex [4]byte
	binary.LittleEndian.PutUint32(bIndex[:], tx.TxIn[idx].PreviousOutPoint.Index)
	sigHash.Write(bIndex[:])

	// Write the previous script bytes
	wire.WriteVarBytes(&sigHash, 0, prevScriptBytes)

	// Next, add the input amount, and sequence number of the input being
	// signed.
	var bAmount [8]byte
	binary.LittleEndian.PutUint64(bAmount[:], uint64(amt))
	sigHash.Write(bAmount[:])
	var bSequence [4]byte
	binary.LittleEndian.PutUint32(bSequence[:], tx.TxIn[idx].Sequence)
	sigHash.Write(bSequence[:])

	branchID := selectBranchID(currentHeight)
	leBranchID := make([]byte, 4)
	binary.LittleEndian.PutUint32(leBranchID, branchID)
	bl, _ := blake2b.New(&blake2b.Config{
		Size:   32,
		Person: append(sigHashPersonalization, leBranchID...),
	})
	bl.Write(sigHash.Bytes())
	h := bl.Sum(nil)
	return h[:], nil
}

// serializeVersion4Transaction serializes a wire.MsgTx into the zcash version four
// wire transaction format.
func serializeVersion4Transaction(tx *wire.MsgTx, expiryHeight uint32) ([]byte, error) {
	var buf bytes.Buffer

	// Write header
	_, err := buf.Write(txHeaderBytes)
	if err != nil {
		return nil, err
	}

	// Write group ID
	_, err = buf.Write(txNVersionGroupIDBytes)
	if err != nil {
		return nil, err
	}

	// Write varint input count
	count := uint64(len(tx.TxIn))
	err = wire.WriteVarInt(&buf, wire.ProtocolVersion, count)
	if err != nil {
		return nil, err
	}

	// Write inputs
	for _, ti := range tx.TxIn {
		// Write outpoint hash
		_, err := buf.Write(ti.PreviousOutPoint.Hash[:])
		if err != nil {
			return nil, err
		}
		// Write outpoint index
		index := make([]byte, 4)
		binary.LittleEndian.PutUint32(index, ti.PreviousOutPoint.Index)
		_, err = buf.Write(index)
		if err != nil {
			return nil, err
		}
		// Write sigscript
		err = wire.WriteVarBytes(&buf, wire.ProtocolVersion, ti.SignatureScript)
		if err != nil {
			return nil, err
		}
		// Write sequence
		sequence := make([]byte, 4)
		binary.LittleEndian.PutUint32(sequence, ti.Sequence)
		_, err = buf.Write(sequence)
		if err != nil {
			return nil, err
		}
	}
	// Write varint output count
	count = uint64(len(tx.TxOut))
	err = wire.WriteVarInt(&buf, wire.ProtocolVersion, count)
	if err != nil {
		return nil, err
	}
	// Write outputs
	for _, to := range tx.TxOut {
		// Write value
		val := make([]byte, 8)
		binary.LittleEndian.PutUint64(val, uint64(to.Value))
		_, err = buf.Write(val)
		if err != nil {
			return nil, err
		}
		// Write pkScript
		err = wire.WriteVarBytes(&buf, wire.ProtocolVersion, to.PkScript)
		if err != nil {
			return nil, err
		}
	}
	// Write nLocktime
	nLockTime := make([]byte, 4)
	binary.LittleEndian.PutUint32(nLockTime, tx.LockTime)
	_, err = buf.Write(nLockTime)
	if err != nil {
		return nil, err
	}

	// Write nExpiryHeight
	expiry := make([]byte, 4)
	binary.LittleEndian.PutUint32(expiry, expiryHeight)
	_, err = buf.Write(expiry)
	if err != nil {
		return nil, err
	}

	// Write nil value balance
	_, err = buf.Write(make([]byte, 8))
	if err != nil {
		return nil, err
	}

	// Write nil value vShieldedSpend
	_, err = buf.Write(make([]byte, 1))
	if err != nil {
		return nil, err
	}

	// Write nil value vShieldedOutput
	_, err = buf.Write(make([]byte, 1))
	if err != nil {
		return nil, err
	}

	// Write nil value vJoinSplit
	_, err = buf.Write(make([]byte, 1))
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func calcHashPrevOuts(tx *wire.MsgTx) []byte {
	var b bytes.Buffer
	for _, in := range tx.TxIn {
		// First write out the 32-byte transaction ID one of whose
		// outputs are being referenced by this input.
		b.Write(in.PreviousOutPoint.Hash[:])

		// Next, we'll encode the index of the referenced output as a
		// little endian integer.
		var buf [4]byte
		binary.LittleEndian.PutUint32(buf[:], in.PreviousOutPoint.Index)
		b.Write(buf[:])
	}
	bl, _ := blake2b.New(&blake2b.Config{
		Size:   32,
		Person: hashPrevOutPersonalization,
	})
	bl.Write(b.Bytes())
	h := bl.Sum(nil)
	return h[:]
}

func calcHashSequence(tx *wire.MsgTx) []byte {
	var b bytes.Buffer
	for _, in := range tx.TxIn {
		var buf [4]byte
		binary.LittleEndian.PutUint32(buf[:], in.Sequence)
		b.Write(buf[:])
	}
	bl, _ := blake2b.New(&blake2b.Config{
		Size:   32,
		Person: hashSequencePersonalization,
	})
	bl.Write(b.Bytes())
	h := bl.Sum(nil)
	return h[:]
}

func calcHashOutputs(tx *wire.MsgTx) []byte {
	var b bytes.Buffer
	for _, out := range tx.TxOut {
		wire.WriteTxOut(&b, 0, 0, out)
	}
	bl, _ := blake2b.New(&blake2b.Config{
		Size:   32,
		Person: hashOutputsPersonalization,
	})
	bl.Write(b.Bytes())
	h := bl.Sum(nil)
	return h[:]
}

func selectBranchID(currentHeight uint64) uint32 {
	return blossomBranchID
}
