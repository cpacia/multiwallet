package bitcoincash

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"github.com/btcsuite/btcd/btcec"
	"github.com/cpacia/multiwallet/base"
	iwallet "github.com/cpacia/wallet-interface"
	"time"
)

type BitcoinCashWallet struct {
	base.WalletBase
}

func NewBitcoinCashWallet() *BitcoinCashWallet {
	w := &BitcoinCashWallet{}
	return w
}

// ValidateAddress validates that the serialization of the address is correct
// for this coin and network. It returns an error if it isn't.
func (w *MockWallet) ValidateAddress(addr iwallet.Address) error {
	if len(addr.String()) != 40 {
		return errors.New("invalid address length")
	}
	if addr.CoinType() != iwallet.CtTestnetMock {
		return errors.New("address's cointype is not CtTestnetMock")
	}
	return nil
}

// IsDust returns whether the amount passed in is considered dust by network. This
// method is called when building payout transactions from the multisig to the various
// participants. If the amount that is supposed to be sent to a given party is below
// the dust threshold, openbazaar-go will not pay that party to avoid building a transaction
// that never confirms.
func (w *MockWallet) IsDust(amount iwallet.Amount) bool {
	return amount.Cmp(iwallet.NewAmount(500)) < 0
}

// EstimateSpendFee should return the anticipated fee to transfer a given amount of coins
// out of the wallet at the provided fee level. Typically this involves building a
// transaction with enough inputs to cover the request amount and calculating the size
// of the transaction. It is OK, if a transaction comes in after this function is called
// that changes the estimated fee as it's only intended to be an estimate.
//
// All amounts should be in the coin's base unit (for example: satoshis).
func (w *MockWallet) EstimateSpendFee(amount iwallet.Amount, feeLevel iwallet.FeeLevel) (iwallet.Amount, error) {
	var fee iwallet.Amount
	switch feeLevel {
	case iwallet.FlEconomic:
		fee = iwallet.NewAmount(250)
	case iwallet.FlNormal:
		fee = iwallet.NewAmount(500)
	case iwallet.FlPriority:
		fee = iwallet.NewAmount(750)
	}
	return fee, nil
}

// Spend is a request to send requested amount to the requested address. The
// fee level is provided by the user. It's up to the implementation to decide
// how best to use the fee level.
//
// The database Tx MUST be respected. When this function is called the wallet
// state changes should be prepped and held in memory. If Rollback() is called
// the state changes should be discarded. Only when Commit() is called should
// the state changes be applied and the transaction broadcasted to the network.
func (w *MockWallet) Spend(tx iwallet.Tx, to iwallet.Address, amt iwallet.Amount, feeLevel iwallet.FeeLevel) (iwallet.TransactionID, error) {
	w.mtx.RLock()
	defer w.mtx.RUnlock()

	// Select fee
	var fee iwallet.Amount
	switch feeLevel {
	case iwallet.FlEconomic:
		fee = iwallet.NewAmount(250)
	case iwallet.FlNormal:
		fee = iwallet.NewAmount(500)
	case iwallet.FlPriority:
		fee = iwallet.NewAmount(750)
	}

	// Keep adding utxos until the total in value is
	// greater than amt + fee
	totalWithFee := amt.Add(fee)
	var (
		totalUtxo iwallet.Amount
		utxos     []mockUtxo
	)
	for _, utxo := range w.utxos {
		utxos = append(utxos, utxo)
		totalUtxo = totalUtxo.Add(utxo.value)

		if totalUtxo.Cmp(totalWithFee) >= 0 {
			break
		}
	}
	if totalUtxo.Cmp(totalWithFee) < 0 {
		return "", errors.New("insufficient funds")
	}

	txidBytes := make([]byte, 32)
	rand.Read(txidBytes)

	txn := iwallet.Transaction{
		ID: iwallet.TransactionID(hex.EncodeToString(txidBytes)),
		To: []iwallet.SpendInfo{
			{
				Address:    to,
				Amount:     amt,
				IsRelevant: false,
				ID:         append(txidBytes, []byte{0x00, 0x00, 0x00, 0x00}...),
			},
		},
	}

	// Maybe add change
	var changeUtxo *mockUtxo
	if totalUtxo.Cmp(totalWithFee) > 0 {
		changeAddr, err := w.newAddress()
		if err != nil {
			return txn.ID, err
		}
		change := iwallet.SpendInfo{
			Address:    changeAddr,
			Amount:     totalUtxo.Sub(amt.Add(fee)),
			IsRelevant: true,
			ID:         append(txidBytes, []byte{0x00, 0x00, 0x00, 0x01}...),
		}
		txn.To = append(txn.To, change)

		changeUtxo = &mockUtxo{
			outpoint: change.ID,
			address:  change.Address,
			value:    change.Amount,
			height:   0,
		}
	}

	var utxosToDelete []string
	for _, utxo := range utxos {
		in := iwallet.SpendInfo{
			ID:         utxo.outpoint,
			Address:    utxo.address,
			Amount:     utxo.value,
			IsRelevant: true,
		}
		txn.From = append(txn.From, in)
		utxosToDelete = append(utxosToDelete, hex.EncodeToString(utxo.outpoint))
	}

	dbTx := tx.(*dbTx)
	dbTx.onCommit = func() error {
		w.mtx.Lock()
		w.transactions[txn.ID] = txn
		for _, utxo := range utxosToDelete {
			delete(w.utxos, utxo)
		}
		if changeUtxo != nil {
			w.utxos[hex.EncodeToString(changeUtxo.outpoint)] = *changeUtxo
			w.addrs[changeUtxo.address] = true
		}
		w.mtx.Unlock()
		if w.outgoing != nil {
			w.outgoing <- txn
		}
		return nil
	}

	return txn.ID, nil
}

// SweepWallet should sweep the full balance of the wallet to the requested
// address. It is expected for most coins that the fee will be subtracted
// from the amount sent rather than added to it.
func (w *MockWallet) SweepWallet(tx iwallet.Tx, to iwallet.Address, feeLevel iwallet.FeeLevel) (iwallet.TransactionID, error) {
	w.mtx.RLock()
	defer w.mtx.RUnlock()

	// Select fee
	var fee iwallet.Amount
	switch feeLevel {
	case iwallet.FlEconomic:
		fee = iwallet.NewAmount(250)
	case iwallet.FlNormal:
		fee = iwallet.NewAmount(500)
	case iwallet.FlPriority:
		fee = iwallet.NewAmount(750)
	}

	var (
		totalUtxo iwallet.Amount
		utxos     []mockUtxo
	)
	for _, utxo := range w.utxos {
		utxos = append(utxos, utxo)
		totalUtxo = totalUtxo.Add(utxo.value)
	}

	txidBytes := make([]byte, 32)
	rand.Read(txidBytes)

	txn := iwallet.Transaction{
		ID: iwallet.TransactionID(hex.EncodeToString(txidBytes)),
		To: []iwallet.SpendInfo{
			{
				Address:    to,
				Amount:     totalUtxo.Sub(fee),
				IsRelevant: false,
				ID:         append(txidBytes, []byte{0x00, 0x00, 0x00, 0x00}...),
			},
		},
	}

	var utxosToDelete []string
	for _, utxo := range utxos {
		in := iwallet.SpendInfo{
			ID:         utxo.outpoint,
			Address:    utxo.address,
			Amount:     utxo.value,
			IsRelevant: true,
		}
		txn.From = append(txn.From, in)
		utxosToDelete = append(utxosToDelete, hex.EncodeToString(utxo.outpoint))
	}

	dbTx := tx.(*dbTx)
	dbTx.onCommit = func() error {
		w.mtx.Lock()
		w.transactions[txn.ID] = txn
		for _, utxo := range utxosToDelete {
			delete(w.utxos, utxo)
		}
		w.mtx.Unlock()
		if w.outgoing != nil {
			w.outgoing <- txn
		}
		return nil
	}

	return txn.ID, nil
}

// EstimateEscrowFee estimates the fee to release the funds from escrow.
// this assumes only one input. If there are more inputs OpenBazaar will
// will add 50% of the returned fee for each additional input. This is a
// crude fee calculating but it simplifies things quite a bit.
func (w *MockWallet) EstimateEscrowFee(threshold int, feeLevel iwallet.FeeLevel) (iwallet.Amount, error) {
	var (
		fee                   iwallet.Amount
		feePerAdditionalInput iwallet.Amount
	)
	switch feeLevel {
	case iwallet.FlEconomic:
		fee = iwallet.NewAmount(250)
		feePerAdditionalInput = iwallet.NewAmount(100)
	case iwallet.FlNormal:
		fee = iwallet.NewAmount(500)
		feePerAdditionalInput = iwallet.NewAmount(200)
	case iwallet.FlPriority:
		fee = iwallet.NewAmount(750)
		feePerAdditionalInput = iwallet.NewAmount(300)
	}
	for i := 0; i < threshold; i++ {
		fee = fee.Add(feePerAdditionalInput)
	}
	return fee, nil
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
func (w *MockWallet) CreateMultisigAddress(keys []btcec.PublicKey, threshold int) (iwallet.Address, []byte, error) {
	var redeemScript []byte
	for _, key := range keys {
		redeemScript = append(redeemScript, key.SerializeCompressed()...)
	}
	t := make([]byte, 4)
	binary.BigEndian.PutUint32(t, uint32(threshold))
	redeemScript = append(redeemScript, t...)

	h := sha256.Sum256(redeemScript)
	addr := iwallet.NewAddress(hex.EncodeToString(h[:]), iwallet.CtTestnetMock)
	return addr, redeemScript, nil
}

// CreateMultisigWithTimeout is the same as CreateMultisigAddress but it adds
// an additional timeout to the address. The address should have two ways to
// release the funds:
//  - m of n signatures are provided (or)
//  - timeout has passed and a signature for timeoutKey is provided.
func (w *MockWallet) CreateMultisigWithTimeout(keys []btcec.PublicKey, threshold int, timeout time.Duration, timeoutKey btcec.PublicKey) (iwallet.Address, []byte, error) {
	var redeemScript []byte
	for _, key := range keys {
		redeemScript = append(redeemScript, key.SerializeCompressed()...)
	}
	t := make([]byte, 4)
	binary.BigEndian.PutUint32(t, uint32(threshold))
	redeemScript = append(redeemScript, t...)
	redeemScript = append(redeemScript, timeoutKey.SerializeCompressed()...)
	u := time.Now().Add(timeout).Unix()
	expiry := make([]byte, 8)
	binary.BigEndian.PutUint64(expiry, uint64(u))
	redeemScript = append(redeemScript, expiry...)

	h := sha256.Sum256(redeemScript)
	addr := iwallet.NewAddress(hex.EncodeToString(h[:]), iwallet.CtTestnetMock)
	return addr, redeemScript, nil
}

// ReleaseFundsAfterTimeout will release funds from the escrow. The signature will
// be created using the timeoutKey.
func (w *MockWallet) ReleaseFundsAfterTimeout(tx iwallet.Tx, txn iwallet.Transaction, timeoutKey btcec.PrivateKey, redeemScript []byte) error {
	w.mtx.RLock()
	defer w.mtx.RUnlock()

	dbtx := tx.(*dbTx)

	txidBytes := make([]byte, 32)
	rand.Read(txidBytes)
	txn.ID = iwallet.TransactionID(hex.EncodeToString(txidBytes))

	expiry := binary.BigEndian.Uint64(redeemScript[len(redeemScript)-8:])
	ts := time.Unix(int64(expiry), 0)

	if ts.After(time.Now()) {
		return errors.New("timeout has not yet passed")
	}

	var utxosToAdd []mockUtxo
	for i, out := range txn.To {
		if _, ok := w.addrs[out.Address]; ok {
			idx := make([]byte, 4)
			binary.BigEndian.PutUint32(idx, uint32(i))
			utxosToAdd = append(utxosToAdd, mockUtxo{
				address:  out.Address,
				value:    out.Amount,
				outpoint: append(txidBytes, idx...),
			})
		}
	}

	dbtx.onCommit = func() error {
		w.mtx.Lock()

		for _, utxo := range utxosToAdd {
			w.utxos[hex.EncodeToString(utxo.outpoint)] = utxo
			w.addrs[utxo.address] = true
		}

		w.transactions[txn.ID] = txn
		w.mtx.Unlock()

		if w.outgoing != nil {
			w.outgoing <- txn
		}

		for _, sub := range w.txSubs {
			sub <- txn
		}
		return nil
	}

	return nil
}

// SignMultisigTransaction should use the provided key to create a signature for
// the multisig transaction. Since this a threshold signature this function will
// separately by each party signing this transaction. The resulting signatures
// will be shared between the relevant parties and one of them will aggregate
// the signatures into a transaction for broadcast.
//
// For coins like bitcoin you may need to return one signature *per input* which is
// why a slice of signatures is returned.
func (w *MockWallet) SignMultisigTransaction(txn iwallet.Transaction, key btcec.PrivateKey, redeemScript []byte) ([]iwallet.EscrowSignature, error) {
	var sigs []iwallet.EscrowSignature
	for i := range txn.From {
		sigBytes := make([]byte, 64)
		rand.Read(sigBytes)

		sigs = append(sigs, iwallet.EscrowSignature{
			Index:     i,
			Signature: sigBytes,
		})
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
func (w *MockWallet) BuildAndSend(tx iwallet.Tx, txn iwallet.Transaction, signatures [][]iwallet.EscrowSignature, redeemScript []byte) error {
	w.mtx.RLock()
	defer w.mtx.RUnlock()

	dbtx := tx.(*dbTx)

	txidBytes := make([]byte, 32)
	rand.Read(txidBytes)
	txn.ID = iwallet.TransactionID(hex.EncodeToString(txidBytes))

	var utxosToAdd []mockUtxo
	for i, out := range txn.To {
		if _, ok := w.addrs[out.Address]; ok {
			idx := make([]byte, 4)
			binary.BigEndian.PutUint32(idx, uint32(i))
			utxosToAdd = append(utxosToAdd, mockUtxo{
				address:  out.Address,
				value:    out.Amount,
				outpoint: append(txidBytes, idx...),
			})
		}
	}

	dbtx.onCommit = func() error {
		w.mtx.Lock()

		for _, utxo := range utxosToAdd {
			w.utxos[hex.EncodeToString(utxo.outpoint)] = utxo
			w.addrs[utxo.address] = true
		}

		w.transactions[txn.ID] = txn
		w.mtx.Unlock()

		if w.outgoing != nil {
			w.outgoing <- txn
		}

		for _, sub := range w.txSubs {
			sub <- txn
		}
		return nil
	}

	return nil
}
