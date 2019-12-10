package bitcoin

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcutil/coinset"
	"github.com/btcsuite/btcutil/hdkeychain"
	"github.com/btcsuite/btcutil/txsort"
	"github.com/btcsuite/btcwallet/wallet/txauthor"
	"github.com/btcsuite/btcwallet/wallet/txrules"
	"github.com/btcsuite/btcwallet/wallet/txsizes"
	"github.com/cpacia/multiwallet/base"
	"github.com/cpacia/multiwallet/client/bchd"
	"github.com/cpacia/multiwallet/database"
	iwallet "github.com/cpacia/wallet-interface"
	"net/http"
	"time"
)

// Assert interfaces
var _ = iwallet.Wallet(&BitcoinWallet{})
var _ = iwallet.WalletCrypter(&BitcoinWallet{})
var _ = iwallet.Escrow(&BitcoinWallet{})
var _ = iwallet.EscrowWithTimeout(&BitcoinWallet{})

var feeLevels = map[iwallet.FeeLevel]iwallet.Amount{
	iwallet.FlEconomic: iwallet.NewAmount(5),
	iwallet.FlNormal:   iwallet.NewAmount(10),
	iwallet.FlPriority: iwallet.NewAmount(20),
}

// BitcoinWallet extends wallet base and implements the
// remaining functions for each interface.
type BitcoinWallet struct {
	base.WalletBase
	testnet  bool
	feeCache *fees
	feeUrl   string
}

// NewBitcoinWallet returns a new BitcoinWallet. This constructor
// attempts to connect to the API. If it fails, it will not build.
func NewBitcoinWallet(cfg *base.WalletConfig) (*BitcoinWallet, error) {
	w := &BitcoinWallet{
		testnet: cfg.Testnet,
		feeUrl:  cfg.FeeUrl,
	}

	chainClient, err := bchd.NewBchdClient(cfg.ClientUrl)
	if err != nil {
		return nil, err
	}

	w.ChainClient = chainClient
	w.DB = cfg.DB
	w.Logger = cfg.Logger
	w.CoinType = iwallet.CtBitcoin
	w.Done = make(chan struct{})
	w.AddressFunc = w.keyToAddress
	return w, nil
}

// ValidateAddress validates that the serialization of the address is correct
// for this coin and network. It returns an error if it isn't.
func (w *BitcoinWallet) ValidateAddress(addr iwallet.Address) error {
	_, err := btcutil.DecodeAddress(addr.String(), w.params())
	return err
}

// IsDust returns whether the amount passed in is considered dust by network. This
// method is called when building payout transactions from the multisig to the various
// participants. If the amount that is supposed to be sent to a given party is below
// the dust threshold, openbazaar-go will not pay that party to avoid building a transaction
// that never confirms.
func (w *BitcoinWallet) IsDust(amount iwallet.Amount) bool {
	return txrules.IsDustAmount(btcutil.Amount(amount.Int64()), 25, txrules.DefaultRelayFeePerKb)
}

// EstimateSpendFee should return the anticipated fee to transfer a given amount of coins
// out of the wallet at the provided fee level. Typically this involves building a
// transaction with enough inputs to cover the request amount and calculating the size
// of the transaction. It is OK, if a transaction comes in after this function is called
// that changes the estimated fee as it's only intended to be an estimate.
//
// All amounts should be in the coin's base unit (for example: satoshis).
func (w *BitcoinWallet) EstimateSpendFee(amount iwallet.Amount, feeLevel iwallet.FeeLevel) (iwallet.Amount, error) {
	amt := iwallet.NewAmount(0)
	err := w.DB.Update(func(dbtx database.Tx) error {
		// Since this is an estimate we can use a dummy output address. Let's use a long one so we don't under estimate.
		addrStr := "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
		if w.testnet {
			addrStr = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"
		}
		tx, err := w.buildTx(dbtx, amount.Int64(), iwallet.NewAddress(addrStr, iwallet.CtBitcoin), feeLevel)
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
func (w *BitcoinWallet) Spend(wtx iwallet.Tx, to iwallet.Address, amt iwallet.Amount, feeLevel iwallet.FeeLevel) (iwallet.TransactionID, error) {
	var (
		txid iwallet.TransactionID
		buf  bytes.Buffer
	)
	err := w.DB.View(func(dbtx database.Tx) error {
		tx, err := w.buildTx(dbtx, amt.Int64(), to, feeLevel)
		if err != nil {
			return err
		}
		txid = iwallet.TransactionID(tx.TxHash().String())
		if err := tx.BtcEncode(&buf, wire.ProtocolVersion, wire.WitnessEncoding); err != nil {
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
				Coin:      iwallet.CtBitcoin,
				TxBytes:   buf.Bytes(),
				Txid:      txid.String(),
			})
			if err != nil {
				return err
			}
			return w.ChainClient.Broadcast(buf.Bytes())
		})
	}
	return txid, err
}

// SweepWallet should sweep the full balance of the wallet to the requested
// address. It is expected for most coins that the fee will be subtracted
// from the amount sent rather than added to it.
func (w *BitcoinWallet) SweepWallet(wtx iwallet.Tx, to iwallet.Address, level iwallet.FeeLevel) (iwallet.TransactionID, error) {
	var (
		txid iwallet.TransactionID
		buf  bytes.Buffer
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
			totalIn += btcutil.Amount(coin.Value().ToUnit(btcutil.AmountSatoshi))

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
		fpb, err := w.feePerByte(level)
		if err != nil {
			return err
		}
		fee := fpb.Mul(iwallet.NewAmount(size)).Int64()

		tx.TxOut[0].Value = int64(totalIn) - fee

		// BIP 69 sorting
		txsort.InPlaceSort(tx)

		// Sign tx
		for i, txIn := range tx.TxIn {
			prevOutScript := additionalPrevScripts[txIn.PreviousOutPoint]
			key := keyMap[txIn.PreviousOutPoint]

			script, err := txscript.WitnessSignature(tx, txscript.NewTxSigHashes(tx), i,
				inVals[txIn.PreviousOutPoint], prevOutScript,
				txscript.SigHashAll, key, true)
			if err != nil {
				return errors.New("failed to sign transaction")
			}
			txIn.Witness = script
		}

		txid = iwallet.TransactionID(tx.TxHash().String())
		if err := tx.BtcEncode(&buf, wire.ProtocolVersion, wire.WitnessEncoding); err != nil {
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
				Coin:      iwallet.CtBitcoin,
				TxBytes:   buf.Bytes(),
				Txid:      txid.String(),
			})
			if err != nil {
				return err
			}
			return w.ChainClient.Broadcast(buf.Bytes())
		})
	}

	return txid, err
}

// EstimateEscrowFee estimates the fee to release the funds from escrow.
// this assumes only one input. If there are more inputs OpenBazaar will
// will add 50% of the returned fee for each additional input. This is a
// crude fee calculating but it simplifies things quite a bit.
func (w *BitcoinWallet) EstimateEscrowFee(threshold int, level iwallet.FeeLevel) (iwallet.Amount, error) {
	var (
		nOuts            = 2
		redeemScriptSize = 4 + (threshold+1)*34
	)
	if threshold == 1 {
		nOuts = 1
	}

	// 8 additional bytes are for version and locktime
	size := 8 + wire.VarIntSerializeSize(1) +
		wire.VarIntSerializeSize(uint64(nOuts)) + 1 +
		threshold*66 + txsizes.P2PKHOutputSize*nOuts + redeemScriptSize

	fpb, err := w.feePerByte(level)
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
func (w *BitcoinWallet) CreateMultisigAddress(keys []btcec.PublicKey, threshold int) (iwallet.Address, []byte, error) {
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
	witnessProgram := sha256.Sum256(redeemScript)
	addr, err := btcutil.NewAddressWitnessScriptHash(witnessProgram[:], w.params())
	if err != nil {
		return iwallet.Address{}, nil, err
	}
	return iwallet.NewAddress(addr.String(), iwallet.CtBitcoin), redeemScript, nil
}

// SignMultisigTransaction should use the provided key to create a signature for
// the multisig transaction. Since this a threshold signature this function will
// separately by each party signing this transaction. The resulting signatures
// will be shared between the relevant parties and one of them will aggregate
// the signatures into a transaction for broadcast.
//
// For coins like bitcoin you may need to return one signature *per input* which is
// why a slice of signatures is returned.
func (w *BitcoinWallet) SignMultisigTransaction(txn iwallet.Transaction, key btcec.PrivateKey, redeemScript []byte) ([]iwallet.EscrowSignature, error) {
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

	privKey, _ := btcec.PrivKeyFromBytes(btcec.S256(), key.Serialize())

	for i := range tx.TxIn {
		sig, err := txscript.RawTxInWitnessSignature(tx, txscript.NewTxSigHashes(tx), i, txn.From[i].Amount.Int64(), redeemScript, txscript.SigHashAll, privKey)
		if err != nil {
			continue
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
func (w *BitcoinWallet) BuildAndSend(wtx iwallet.Tx, txn iwallet.Transaction, signatures [][]iwallet.EscrowSignature, redeemScript []byte) (iwallet.TransactionID, error) {
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

	// Check if time locked
	var timeLocked bool
	if redeemScript[0] == txscript.OP_IF {
		timeLocked = true
	}

	for i := range tx.TxIn {
		witness := [][]byte{{}}
		for _, escrowSigs := range signatures {
			for _, sig := range escrowSigs {
				if sig.Index == i {
					witness = append(witness, append(sig.Signature, byte(txscript.SigHashAll)))
					break
				}
			}
		}

		if timeLocked {
			witness = append(witness, []byte{0x01})
		}

		witness = append(witness, redeemScript)
		tx.TxIn[i].Witness = witness
	}

	txid := iwallet.TransactionID(tx.TxHash().String())

	var buf bytes.Buffer
	if err := tx.BtcEncode(&buf, wire.ProtocolVersion, wire.WitnessEncoding); err != nil {
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
				Coin:      iwallet.CtBitcoin,
				TxBytes:   buf.Bytes(),
				Txid:      tx.TxHash().String(),
			})
			if err != nil {
				return err
			}
			return w.ChainClient.Broadcast(buf.Bytes())
		})
	}

	return txid, nil
}

// CreateMultisigWithTimeout is the same as CreateMultisigAddress but it adds
// an additional timeout to the address. The address should have two ways to
// release the funds:
//  - m of n signatures are provided (or)
//  - timeout has passed and a signature for timeoutKey is provided.
func (w *BitcoinWallet) CreateMultisigWithTimeout(keys []btcec.PublicKey, threshold int, timeout time.Duration, timeoutKey btcec.PublicKey) (iwallet.Address, []byte, error) {
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
	sequenceLock := blockchain.LockTimeToSequence(false, uint32(timeout.Hours()*6))
	builder.AddOp(txscript.OP_IF)
	builder.AddInt64(int64(threshold))
	for _, key := range keys {
		builder.AddData(key.SerializeCompressed())
	}
	builder.AddInt64(int64(len(keys)))
	builder.AddOp(txscript.OP_CHECKMULTISIG)
	builder.AddOp(txscript.OP_ELSE).
		AddInt64(int64(sequenceLock)).
		AddOp(txscript.OP_CHECKSEQUENCEVERIFY).
		AddOp(txscript.OP_DROP).
		AddData(timeoutKey.SerializeCompressed()).
		AddOp(txscript.OP_CHECKSIG).
		AddOp(txscript.OP_ENDIF)

	redeemScript, err := builder.Script()
	if err != nil {
		return iwallet.Address{}, nil, err
	}
	witnessProgram := sha256.Sum256(redeemScript)
	addr, err := btcutil.NewAddressWitnessScriptHash(witnessProgram[:], w.params())
	if err != nil {
		return iwallet.Address{}, nil, err
	}
	return iwallet.NewAddress(addr.String(), iwallet.CtBitcoin), redeemScript, nil
}

// ReleaseFundsAfterTimeout will release funds from the escrow. The signature will
// be created using the timeoutKey.
func (w *BitcoinWallet) ReleaseFundsAfterTimeout(wtx iwallet.Tx, txn iwallet.Transaction, timeoutKey btcec.PrivateKey, redeemScript []byte) (iwallet.TransactionID, error) {
	tx := wire.NewMsgTx(2)
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

	// BIP 69 sorting
	txsort.InPlaceSort(tx)

	privKey, _ := btcec.PrivKeyFromBytes(btcec.S256(), timeoutKey.Serialize())

	locktime, err := lockTimeFromRedeemScript(redeemScript)
	if err != nil {
		return iwallet.TransactionID(""), err
	}
	for i := range tx.TxIn {
		tx.TxIn[i].Sequence = locktime
	}

	for i := range tx.TxIn {
		sig, err := txscript.RawTxInWitnessSignature(tx, txscript.NewTxSigHashes(tx), i, txn.From[i].Amount.Int64(), redeemScript, txscript.SigHashAll, privKey)
		if err != nil {
			return iwallet.TransactionID(""), err
		}
		witness := [][]byte{sig, {}, redeemScript}
		tx.TxIn[i].Witness = witness
	}

	txid := iwallet.TransactionID(tx.TxHash().String())

	var buf bytes.Buffer
	if err := tx.BtcEncode(&buf, wire.ProtocolVersion, wire.WitnessEncoding); err != nil {
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
				Coin:      iwallet.CtBitcoin,
				TxBytes:   buf.Bytes(),
				Txid:      tx.TxHash().String(),
			})
			if err != nil {
				return err
			}
			return w.ChainClient.Broadcast(buf.Bytes())
		})
	}

	return txid, nil
}

func (w *BitcoinWallet) params() *chaincfg.Params {
	if w.testnet {
		return &chaincfg.TestNet3Params
	} else {
		return &chaincfg.MainNetParams
	}
}

type fees struct {
	Priority uint64 `json:"priority"`
	Normal   uint64 `json:"normal"`
	Economic uint64 `json:"economic"`
	expires  time.Time
}

func (w *BitcoinWallet) feePerByte(level iwallet.FeeLevel) (iwallet.Amount, error) {
	selectFee := func(level iwallet.FeeLevel, fee fees) iwallet.Amount {
		switch level {
		case iwallet.FlEconomic:
			return iwallet.NewAmount(fee.Economic)
		case iwallet.FlPriority:
			return iwallet.NewAmount(fee.Priority)
		default:
			return iwallet.NewAmount(fee.Normal)
		}
	}

	if w.feeCache != nil && w.feeCache.expires.Before(time.Now()) {
		return selectFee(level, *w.feeCache), nil
	}

	resp, err := http.Get(w.feeUrl)
	if err != nil {
		return feeLevels[level], nil
	}
	decoder := json.NewDecoder(resp.Body)

	var f fees
	if err := decoder.Decode(&f); err != nil {
		return feeLevels[level], nil
	}
	f.expires = time.Now().Add(time.Hour)
	w.feeCache = &f

	return selectFee(level, *w.feeCache), nil
}

func (w *BitcoinWallet) buildTx(dbtx database.Tx, amount int64, iaddr iwallet.Address, feeLevel iwallet.FeeLevel) (*wire.MsgTx, error) {
	// Check for dust
	addr, err := btcutil.DecodeAddress(iaddr.String(), w.params())
	if err != nil {
		return nil, err
	}
	script, err := txscript.PayToAddrScript(addr)
	if err != nil {
		return nil, err
	}
	if txrules.IsDustAmount(btcutil.Amount(amount), len(script), txrules.DefaultRelayFeePerKb) {
		return nil, errors.New("dust output amount")
	}

	var (
		additionalKeysByScript = make(map[wire.OutPoint]*btcutil.WIF)
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
	inputSource := func(target btcutil.Amount) (total btcutil.Amount, inputs []*wire.TxIn, inputValues []btcutil.Amount, scripts [][]byte, err error) {
		coinSelector := coinset.MaxValueAgeCoinSelector{MaxInputs: 10000, MinChangeAmount: btcutil.Amount(0)}
		coins, err := coinSelector.CoinSelect(btcutil.Amount(target.ToUnit(btcutil.AmountSatoshi)), allCoins)
		if err != nil {
			err = base.ErrInsufficientFunds
			return
		}
		for _, c := range coins.Coins() {
			total += btcutil.Amount(c.Value().ToUnit(btcutil.AmountSatoshi))

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
			wif, werr := btcutil.NewWIF(privKey, w.params(), true)
			if werr != nil {
				err = werr
				return
			}

			additionalKeysByScript[*outpoint] = wif

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

			sat := c.Value().ToUnit(btcutil.AmountSatoshi)
			inVals[*outpoint] = int64(sat)
		}
		return total, inputs, inputValues, scripts, nil
	}

	// Get the fee per kilobyte
	fpb, err := w.feePerByte(feeLevel)
	if err != nil {
		return nil, err
	}
	feePerKB := fpb.Int64() * 1000

	// outputs
	out := wire.NewTxOut(amount, script)

	// Create change source
	changeSource := func() ([]byte, error) {
		iaddr, err := w.Keychain.CurrentAddressWithTx(dbtx, true)
		if err != nil {
			return nil, err
		}

		addr, err := btcutil.DecodeAddress(iaddr.String(), w.params())
		if err != nil {
			return nil, err
		}

		script, err := txscript.PayToAddrScript(addr)
		if err != nil {
			return nil, err
		}
		return script, nil
	}

	// Build transaction
	authoredTx, err := txauthor.NewUnsignedTransaction([]*wire.TxOut{out}, btcutil.Amount(feePerKB), inputSource, changeSource)
	if err != nil {
		return nil, err
	}

	// BIP 69 sorting
	txsort.InPlaceSort(authoredTx.Tx)

	// Sign tx
	tx := authoredTx.Tx
	for i, txIn := range tx.TxIn {
		prevOutScript := additionalPrevScripts[txIn.PreviousOutPoint]
		wif := additionalKeysByScript[txIn.PreviousOutPoint]

		script, err := txscript.WitnessSignature(tx, txscript.NewTxSigHashes(tx), i,
			inVals[txIn.PreviousOutPoint], prevOutScript,
			txscript.SigHashAll, wif.PrivKey, true)
		if err != nil {
			return nil, fmt.Errorf("failed to sign transaction: %s", err)
		}
		tx.TxIn[i].Witness = script
	}
	return tx, nil
}

func (w *BitcoinWallet) keyToAddress(key *hdkeychain.ExtendedKey) (iwallet.Address, error) {
	newKey, err := hdkeychain.NewKeyFromString(key.String())
	if err != nil {
		return iwallet.Address{}, err
	}
	addr, err := newKey.Address(w.params())
	if err != nil {
		return iwallet.Address{}, err
	}
	witnessAddr, err := btcutil.NewAddressWitnessPubKeyHash(addr.ScriptAddress(), w.params())
	if err != nil {
		return iwallet.Address{}, err
	}
	return iwallet.NewAddress(witnessAddr.String(), iwallet.CtBitcoin), nil
}

func lockTimeFromRedeemScript(redeemScript []byte) (uint32, error) {
	if len(redeemScript) < 113 {
		return 0, errors.New("redeem script invalid length")
	}
	if redeemScript[106] != 103 {
		return 0, errors.New("invalid redeem script")
	}
	if redeemScript[107] == 0 {
		return 0, nil
	}
	if 81 <= redeemScript[107] && redeemScript[107] <= 96 {
		return uint32((redeemScript[107] - 81) + 1), nil
	}
	var v []byte
	op := redeemScript[107]
	if 1 <= op && op <= 75 {
		for i := 0; i < int(op); i++ {
			v = append(v, []byte{redeemScript[108+i]}...)
		}
	} else {
		return 0, errors.New("too many bytes pushed for sequence")
	}
	var result int64
	for i, val := range v {
		result |= int64(val) << uint8(8*i)
	}

	return uint32(result), nil
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
