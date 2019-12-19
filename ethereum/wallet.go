package ethereum

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcutil/hdkeychain"
	"github.com/cpacia/multiwallet/base"
	"github.com/cpacia/multiwallet/client/ethclient"
	"github.com/cpacia/multiwallet/database"
	iwallet "github.com/cpacia/wallet-interface"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	ethc "github.com/ethereum/go-ethereum/ethclient"
	"github.com/gcash/bchutil"
	"math/big"
	"strings"
	"time"
)

// Assert interfaces
var _ = iwallet.Wallet(&EthereumWallet{})
var _ = iwallet.WalletCrypter(&EthereumWallet{})
var _ = iwallet.Escrow(&EthereumWallet{})
var _ = iwallet.EscrowWithTimeout(&EthereumWallet{})

const (
	// RegistryAddressMainnet represents the address of the OpenBazaar escrow contract on mainnet.
	RegistryAddressMainnet = "0x5c69ccf91eab4ef80d9929b3c1b4d5bc03eb0981"
	// RegistryAddressRinkeby represents the address of the OpenBazaar escrow contract on the Rinkeby testnet.
	RegistryAddressRinkeby = "0x5cEF053c7b383f430FC4F4e1ea2F7D31d8e2D16C"
	// RegistryAddressRopsten represents the address of the OpenBazaar escrow contract on Ropsten testnet.
	RegistryAddressRopsten = "0x403d907982474cdd51687b09a8968346159378f3"
)

// EthereumWallet extends wallet base and implements the
// remaining functions for each interface.
type EthereumWallet struct {
	base.WalletBase
	testnet  bool
	client   *ethclient.EthClient
	registry *Registry
}

// NewEthereumWallet returns a new EthereumWallet. This constructor
// attempts to connect to the API. If it fails, it will not build.
func NewEthereumWallet(cfg *base.WalletConfig) (*EthereumWallet, error) {
	w := &EthereumWallet{
		testnet: cfg.Testnet,
	}

	w.KeychainOpts = []base.KeychainOption{
		func(config *base.KeychainConfig) error {
			config.DisableMarkAsUsed = true
			config.LookaheadWindowSize = 1
			config.ExternalOnly = true
			return nil
		},
	}

	regAddr := RegistryAddressMainnet
	if cfg.Testnet {
		regAddr = RegistryAddressRinkeby
	}

	createRegistry := func(rpc *ethc.Client) (*common.Address, error) {
		reg, err := NewRegistry(common.HexToAddress(regAddr), rpc)
		if err != nil {
			return nil, err
		}

		v, err := reg.GetRecommendedVersion(nil, "escrow")
		if err != nil {
			return nil, err
		}

		w.registry = reg
		return &v.Implementation, nil
	}

	client, err := ethclient.NewEthClient(cfg.ClientUrl, createRegistry)
	if err != nil {
		return nil, err
	}

	w.client = client
	w.ChainClient = client
	w.DB = cfg.DB
	w.Logger = cfg.Logger
	w.CoinType = iwallet.CtEthereum
	w.Done = make(chan struct{})
	w.AddressFunc = w.keyToAddress

	return w, nil
}

// NewAddress should return a new, never before used address. This is called
// by OpenBazaar to get a fresh address for a direct payment order. It
// associates this address with the order and assumes if a payment is received
// by this address that it is for the order. Failure to return a never before
// used address could put the order in a bad state.
//
// Wallets that only use a single address, like Ethereum, should save the
// passed in order ID locally such as to associate payments with orders.
func (w *EthereumWallet) NewAddress() (iwallet.Address, error) {
	addr, err := w.Keychain.CurrentAddress(false)
	if err != nil {
		return addr, err
	}

	// Since this is only used for direct orders, we're going to pad the address
	// with a random nonce so that we can associate it with the order.
	r := make([]byte, 20)
	rand.Read(r)
	return iwallet.NewAddress(addr.String()+hex.EncodeToString(r), iwallet.CtEthereum), nil
}

// ValidateAddress validates that the serialization of the address is correct
// for this coin and network. It returns an error if it isn't.
func (w *EthereumWallet) ValidateAddress(addr iwallet.Address) error {
	// Check standard
	if !common.IsHexAddress(addr.String()) {
		// Check our custom escrow format
		if !strings.HasPrefix(addr.String(), "0x") || len(addr.String()) != 66 {
			return errors.New("invalid ethereum address")
		}
	}
	return nil
}

// IsDust returns whether the amount passed in is considered dust by network. This
// method is called when building payout transactions from the multisig to the various
// participants. If the amount that is supposed to be sent to a given party is below
// the dust threshold, openbazaar-go will not pay that party to avoid building a transaction
// that never confirms.
func (w *EthereumWallet) IsDust(amount iwallet.Amount) bool {
	// TODO:
	return false
}

// Balance should return the confirmed and unconfirmed balance for the wallet.
func (w *EthereumWallet) Balance() (unconfirmed iwallet.Amount, confirmed iwallet.Amount, err error) {
	return iwallet.NewAmount(0), iwallet.NewAmount(0), nil
}

// WatchAddress is used by the escrow system to tell the wallet to listen
// on the escrow address. It's expected that payments into and spends from
// this address will be pushed back to OpenBazaar.
//
// Note a database transaction is used here. Same rules of Commit() and
// Rollback() apply.
func (w *EthereumWallet) WatchAddress(tx iwallet.Tx, addrs ...iwallet.Address) error {
	//TODO:
	return nil
}

// EstimateSpendFee should return the anticipated fee to transfer a given amount of coins
// out of the wallet at the provided fee level. Typically this involves building a
// transaction with enough inputs to cover the request amount and calculating the size
// of the transaction. It is OK, if a transaction comes in after this function is called
// that changes the estimated fee as it's only intended to be an estimate.
//
// All amounts should be in the coin's base unit (for example: satoshis).
func (w *EthereumWallet) EstimateSpendFee(amount iwallet.Amount, feeLevel iwallet.FeeLevel) (iwallet.Amount, error) {
	// TODO:
	return iwallet.NewAmount(0), nil
}

// Spend is a request to send requested amount to the requested address. The
// fee level is provided by the user. It's up to the implementation to decide
// how best to use the fee level.
//
// The database Tx MUST be respected. When this function is called the wallet
// state changes should be prepped and held in memory. If Rollback() is called
// the state changes should be discarded. Only when Commit() is called should
// the state changes be applied and the transaction broadcasted to the network.
func (w *EthereumWallet) Spend(wtx iwallet.Tx, to iwallet.Address, amt iwallet.Amount, feeLevel iwallet.FeeLevel) (iwallet.TransactionID, error) {
	wbtx, ok := wtx.(*base.DBTx)
	if !ok {
		return iwallet.TransactionID(""), errors.New("tx is not expected type")
	}

	addr, err := w.Keychain.CurrentAddress(false)
	if err != nil {
		return iwallet.TransactionID(""), err
	}

	var (
		txhash    iwallet.TransactionID
		walletKey *hdkeychain.ExtendedKey
		signedTx  *types.Transaction
		from      = iwallet.NewAddress(addr.String(), iwallet.CtEthereum)
	)
	err = w.DB.View(func(dbtx database.Tx) error {
		walletKey, err = w.Keychain.KeyForAddress(dbtx, from, nil)
		return err
	})
	if err != nil {
		return txhash, err
	}

	priv, err := walletKey.ECPrivKey()
	if err != nil {
		return txhash, err
	}

	account := Account{
		PrivateKey: priv.ToECDSA(),
		Addr:       common.HexToAddress(addr.String()),
	}

	gas, err := w.gas(feeLevel)
	if err != nil {
		return txhash, err
	}

	if common.IsHexAddress(to.String()) { // Sending to a normal eth address
		bigAmt := big.Int(amt)
		signedTx, err = w.buildTx(&account, common.HexToAddress(to.String()), &bigAmt, false, gas, nil)
		if err != nil {
			return txhash, err
		}
		txhash = iwallet.TransactionID(signedTx.Hash().String())
	} else if strings.HasPrefix(to.String(), "0x") && len(to.String()) == 82 { // Sending to a direct address
		data, err := hex.DecodeString(strings.TrimPrefix(to.String(), "0x"))
		if err != nil {
			return txhash, err
		}

		bigAmt := big.Int(amt)
		signedTx, err = w.buildTx(&account, common.HexToAddress(to.String()[:42]), &bigAmt, false, gas, data)
		if err != nil {
			return txhash, err
		}
		txhash = iwallet.TransactionID(signedTx.Hash().String())
	} else if strings.HasPrefix(to.String(), "0x") && len(to.String()) == 66 { // Sending to an escrow address
		// TODO:
	} else {
		return iwallet.TransactionID(""), errors.New("unknown address type")
	}

	wbtx.OnCommit = func() error {
		return w.DB.Update(func(dbtx database.Tx) error {
			txn := iwallet.Transaction{
				ID:        txhash,
				Value:     amt.Mul(iwallet.NewAmount(-1)),
				Timestamp: time.Now(),
				From: []iwallet.SpendInfo{
					{
						Amount:  amt,
						Address: iwallet.NewAddress(addr.String(), iwallet.CtEthereum),
					},
				},
				To: []iwallet.SpendInfo{
					{
						Amount:  amt,
						Address: to,
					},
				},
			}
			if err := dbtx.Save(&txn); err != nil {
				return err
			}
			return w.client.Broadcast(nil)
		})
	}

	return txhash, nil
}

// SweepWallet should sweep the full balance of the wallet to the requested
// address. It is expected for most coins that the fee will be subtracted
// from the amount sent rather than added to it.
func (w *EthereumWallet) SweepWallet(wtx iwallet.Tx, to iwallet.Address, level iwallet.FeeLevel) (iwallet.TransactionID, error) {
	from, err := w.Keychain.CurrentAddress(false)
	if err != nil {
		return iwallet.TransactionID(""), err
	}

	wbtx, ok := wtx.(*base.DBTx)
	if !ok {
		return iwallet.TransactionID(""), errors.New("tx is not expected type")
	}

	var walletKey *hdkeychain.ExtendedKey
	err = w.DB.View(func(dbtx database.Tx) error {
		walletKey, err = w.Keychain.KeyForAddress(dbtx, from, nil)
		return err
	})
	if err != nil {
		return iwallet.TransactionID(""), err
	}

	priv, err := walletKey.ECPrivKey()
	if err != nil {
		return iwallet.TransactionID(""), err
	}

	account := Account{
		PrivateKey: priv.ToECDSA(),
		Addr:       common.HexToAddress(from.String()),
	}

	gas, err := w.gas(level)
	if err != nil {
		return iwallet.TransactionID(""), err
	}
	signedTx, err := w.buildTx(&account, common.HexToAddress(to.String()), big.NewInt(0), true, gas, nil)
	if err != nil {
		return iwallet.TransactionID(""), err
	}

	txhash := iwallet.TransactionID(signedTx.Hash().String())

	wbtx.OnCommit = func() error {
		return w.DB.Update(func(dbtx database.Tx) error {
			txn := iwallet.Transaction{
				ID:        txhash,
				Value:     iwallet.NewAmount(signedTx.Value()).Mul(iwallet.NewAmount(-1)),
				Timestamp: time.Now(),
				From: []iwallet.SpendInfo{
					{
						Amount:  iwallet.NewAmount(signedTx.Value()),
						Address: iwallet.NewAddress(from.String(), iwallet.CtEthereum),
					},
				},
				To: []iwallet.SpendInfo{
					{
						Amount:  iwallet.NewAmount(signedTx.Value()),
						Address: to,
					},
				},
			}
			if err := dbtx.Save(&txn); err != nil {
				return err
			}
			return w.client.Broadcast(nil)
		})
	}
	return txhash, nil
}

// EstimateEscrowFee estimates the fee to release the funds from escrow.
// this assumes only one input. If there are more inputs OpenBazaar will
// will add 50% of the returned fee for each additional input. This is a
// crude fee calculating but it simplifies things quite a bit.
func (w *EthereumWallet) EstimateEscrowFee(threshold int, level iwallet.FeeLevel) (iwallet.Amount, error) {
	// TODO:
	return iwallet.NewAmount(0), nil
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
func (w *EthereumWallet) CreateMultisigAddress(keys []btcec.PublicKey, threshold int) (iwallet.Address, []byte, error) {
	if len(keys) < threshold {
		return iwallet.Address{}, nil, fmt.Errorf("unable to generate multisig script with "+
			"%d required signatures when there are only %d public "+
			"keys available", threshold, len(keys))
	}

	if len(keys) < 2 || len(keys) > 3 {
		return iwallet.Address{}, nil, fmt.Errorf("unable to generate multisig script with %d keys", len(keys))
	}

	var serializedKeys []byte
	for _, key := range keys {
		serializedKeys = append(serializedKeys, key.SerializeCompressed()...)
	}
	id := bchutil.Hash160(serializedKeys)

	addrs := make([]common.Address, 3)
	for i, key := range keys {
		ePubkey := key.ToECDSA()
		addrs[i] = crypto.PubkeyToAddress(*ePubkey)
	}

	ver, err := w.registry.GetRecommendedVersion(nil, "escrow")
	if err != nil {
		return iwallet.Address{}, nil, err
	}

	script := EthRedeemScript{
		TxnID:           id,
		Buyer:           addrs[0],
		Vendor:          addrs[1],
		Threshold:       uint8(threshold),
		MultisigAddress: ver.Implementation,
	}

	if len(keys) > 2 {
		script.Moderator = addrs[2]
	}

	redeemScript, err := script.Serialize()
	if err != nil {
		return iwallet.Address{}, nil, err
	}

	scriptHash, err := script.ScriptHash()
	if err != nil {
		return iwallet.Address{}, nil, err
	}

	// Here we are setting the escrow address to the hex encoded 32 byte hash of the redeem script.
	// Since it is expected the keys passed in to this method are unique per order, this address
	// should also end up unique per order. Note a standard ethereum address is 20 bytes, but our
	// escrow addresses are 32 bytes.
	addr := iwallet.NewAddress("0x"+hex.EncodeToString(scriptHash[:]), iwallet.CtEthereum)

	err = w.DB.Update(func(tx database.Tx) error {
		return tx.Save(&database.WatchedAddressRecord{
			Addr:   addr.String(),
			Coin:   w.CoinType.CurrencyCode(),
			Script: redeemScript,
		})
	})
	if err != nil {
		return iwallet.Address{}, nil, err
	}

	return addr, redeemScript, nil
}

// SignMultisigTransaction should use the provided key to create a signature for
// the multisig transaction. Since this a threshold signature this function will
// separately by each party signing this transaction. The resulting signatures
// will be shared between the relevant parties and one of them will aggregate
// the signatures into a transaction for broadcast.
//
// For coins like bitcoin you may need to return one signature *per input* which is
// why a slice of signatures is returned.
func (w *EthereumWallet) SignMultisigTransaction(txn iwallet.Transaction, key btcec.PrivateKey, redeemScript []byte) ([]iwallet.EscrowSignature, error) {
	// TODO:
	return nil, nil
}

// BuildAndSend should used the passed in signatures to build the transaction.
// Note the signatures are a slice of slices. This is because coins like Bitcoin
// may require one signature *per input*. In this case the outer slice is the
// signatures from the different key holders and the inner slice is the keys
// per input.
// (TransactionID,
// Note a database transaction is used here. Same rules of Commit() and
// Rollback() apply.
func (w *EthereumWallet) BuildAndSend(dbtx iwallet.Tx, txn iwallet.Transaction, signatures [][]iwallet.EscrowSignature, redeemScript []byte) (iwallet.TransactionID, error) {
	// TODO:
	return iwallet.TransactionID(""), nil
}

// CreateMultisigWithTimeout is the same as CreateMultisigAddress but it adds
// an additional timeout to the address. The address should have two ways to
// release the funds:
//  - m of n signatures are provided (or)
//  - timeout has passed and a signature for timeoutKey is provided.
func (w *EthereumWallet) CreateMultisigWithTimeout(keys []btcec.PublicKey, threshold int, timeout time.Duration, timeoutKey btcec.PublicKey) (iwallet.Address, []byte, error) {
	if len(keys) < threshold {
		return iwallet.Address{}, nil, fmt.Errorf("unable to generate multisig script with "+
			"%d required signatures when there are only %d public "+
			"keys available", threshold, len(keys))
	}

	if len(keys) < 2 || len(keys) > 3 {
		return iwallet.Address{}, nil, fmt.Errorf("unable to generate multisig script with %d keys", len(keys))
	}

	if keys[1] != timeoutKey {
		return iwallet.Address{}, nil, fmt.Errorf("timeout key does not match key at index 2")
	}

	var serializedKeys []byte
	for _, key := range keys {
		serializedKeys = append(serializedKeys, key.SerializeCompressed()...)
	}
	id := bchutil.Hash160(serializedKeys)

	addrs := make([]common.Address, 3)
	for i, key := range keys {
		ePubkey := key.ToECDSA()
		addrs[i] = crypto.PubkeyToAddress(*ePubkey)
	}

	ver, err := w.registry.GetRecommendedVersion(nil, "escrow")
	if err != nil {
		return iwallet.Address{}, nil, err
	}

	script := EthRedeemScript{
		TxnID:           id,
		Buyer:           addrs[0],
		Vendor:          addrs[1],
		Threshold:       uint8(threshold),
		Timeout:         uint32(timeout.Seconds()),
		MultisigAddress: ver.Implementation,
	}

	if len(keys) > 2 {
		script.Moderator = addrs[2]
	}

	redeemScript, err := script.Serialize()
	if err != nil {
		return iwallet.Address{}, nil, err
	}

	scriptHash, err := script.ScriptHash()
	if err != nil {
		return iwallet.Address{}, nil, err
	}

	// Here we are setting the escrow address to the hex encoded 32 byte hash of the redeem script.
	// Since it is expected the keys passed in to this method are unique per order, this address
	// should also end up unique per order. Note a standard ethereum address is 20 bytes, but our
	// escrow addresses are 32 bytes.
	addr := iwallet.NewAddress("0x"+hex.EncodeToString(scriptHash[:]), iwallet.CtEthereum)

	err = w.DB.Update(func(tx database.Tx) error {
		return tx.Save(&database.WatchedAddressRecord{
			Addr:   addr.String(),
			Coin:   w.CoinType.CurrencyCode(),
			Script: redeemScript,
		})
	})
	if err != nil {
		return iwallet.Address{}, nil, err
	}

	return addr, redeemScript, nil
}

// ReleaseFundsAfterTimeout will release funds from the escrow. The signature will
// be created using the timeoutKey.
func (w *EthereumWallet) ReleaseFundsAfterTimeout(dbtx iwallet.Tx, txn iwallet.Transaction, timeoutKey btcec.PrivateKey, redeemScript []byte) (iwallet.TransactionID, error) {
	// TODO:
	return iwallet.TransactionID(""), nil
}

func (w *EthereumWallet) buildTx(from *Account, destAccount common.Address, value *big.Int, spendAll bool, fee big.Int, data []byte) (*types.Transaction, error) {
	var err error
	fromAddress := from.Address()
	nonce, err := w.client.RPC.PendingNonceAt(context.Background(), fromAddress)
	if err != nil {
		return nil, err
	}

	gasPrice, err := w.client.RPC.SuggestGasPrice(context.Background())
	if err != nil {
		return nil, err
	}

	if gasPrice.Int64() < fee.Int64() {
		gasPrice = &fee
	}

	tvalue := value

	msg := ethereum.CallMsg{From: fromAddress, Value: tvalue}
	gasLimit, err := w.client.RPC.EstimateGas(context.Background(), msg)
	if err != nil {
		return nil, err
	}

	// if spend all then we need to set the value = confirmedBalance - gas
	if spendAll {
		_, confirmed, err := w.Balance()
		if err != nil {
			//currentBalance = big.NewInt(0)
			return nil, err
		}
		bigConfirmed := big.Int(confirmed)
		gas := new(big.Int).Mul(gasPrice, big.NewInt(int64(gasLimit)))

		if bigConfirmed.Cmp(gas) >= 0 {
			tvalue = new(big.Int).Sub(&bigConfirmed, gas)
		}
	}

	rawTx := types.NewTransaction(nonce, destAccount, tvalue, gasLimit, gasPrice, data)
	signedTx, err := from.SignTransaction(types.HomesteadSigner{}, rawTx)
	if err != nil {
		return nil, err
	}
	return signedTx, nil
}

func (w *EthereumWallet) gas(level iwallet.FeeLevel) (big.Int, error) {
	est, err := w.client.GetEthGasStationEstimate()
	ret := big.NewInt(0)
	if err != nil {
		return *ret, err
	}
	switch level {
	case iwallet.FlNormal:
		ret, _ = big.NewFloat(est.Average * 100000000).Int(nil)
	case iwallet.FlEconomic:
		ret, _ = big.NewFloat(est.SafeLow * 100000000).Int(nil)
	case iwallet.FlPriority:
		ret, _ = big.NewFloat(est.Fast * 100000000).Int(nil)
	}
	return *ret, nil
}

func (w *EthereumWallet) keyToAddress(key *hdkeychain.ExtendedKey) (iwallet.Address, error) {
	pubkey, err := key.ECPubKey()
	if err != nil {
		return iwallet.Address{}, err
	}
	ecdsaPubkey := pubkey.ToECDSA()
	addr := crypto.PubkeyToAddress(*ecdsaPubkey)

	return iwallet.NewAddress(addr.String(), iwallet.CtEthereum), nil
}

// newKeyedTransactor is a hack to allow us to get the txid of a smart contract transaction
//  before the transaction is broadcast to the network. If hashChan is not nil, the txid
// will be returned over the chan and the smart contract will not be executed. If it is nil
// then it will be executed as normal. Thus to make a transaction AND get the ID before hand,
// this will have to be called twice.
func newKeyedTransactor(key *ecdsa.PrivateKey, hashChan chan common.Hash) *bind.TransactOpts {
	keyAddr := crypto.PubkeyToAddress(key.PublicKey)
	return &bind.TransactOpts{
		From: keyAddr,
		Signer: func(signer types.Signer, address common.Address, tx *types.Transaction) (*types.Transaction, error) {
			if address != keyAddr {
				return nil, errors.New("not authorized to sign this account")
			}
			signature, err := crypto.Sign(signer.Hash(tx).Bytes(), key)
			if err != nil {
				return nil, err
			}
			signedTx, err := tx.WithSignature(signer, signature)
			if err != nil {
				return nil, err
			}
			if hashChan != nil {
				hashChan <- signedTx.Hash()
				return nil, errors.New("transactor is sign only")
			}
			return signedTx, nil
		},
	}
}
