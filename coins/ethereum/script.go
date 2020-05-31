package ethereum

import (
	"bytes"
	"encoding/binary"
	"encoding/gob"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// EthRedeemScript is used to represent redeem script for eth wallet
// <uniqueId: 20><threshold:1><timeoutHours:4><buyer:20><seller:20>
// <moderator:20><multisigAddress:20><tokenAddress:20>
type EthRedeemScript struct {
	TxnID           [20]byte
	Threshold       uint8
	Timeout         uint32
	Buyer           common.Address
	Vendor          common.Address
	Moderator       common.Address
	MultisigAddress common.Address
	TokenAddress    common.Address
}

// Serialize returns a serialization of the redeemScript.
func (e *EthRedeemScript) Serialize() ([]byte, error) {
	var buf bytes.Buffer
	encoder := gob.NewEncoder(&buf)
	err := encoder.Encode(e)
	return buf.Bytes(), err
}

// Deserialize unmarshals the byte slice into a EthRedeemScript.
func (e *EthRedeemScript) Deserialize(b []byte) error {
	buf := bytes.NewBuffer(b)
	d := gob.NewDecoder(buf)
	err := d.Decode(e)
	return err
}

// ScriptHash returns the hash of the redeem script as used by the
// smart contract.
func (e *EthRedeemScript) ScriptHash() ([32]byte, error) {
	serializedTimeout := make([]byte, 4)
	binary.BigEndian.PutUint32(serializedTimeout, e.Timeout)

	ser := append(e.TxnID[:], append([]byte{e.Threshold},
		append(serializedTimeout[:], append(e.Buyer.Bytes(),
			append(e.Vendor.Bytes(), append(e.Moderator.Bytes(),
				append(e.MultisigAddress.Bytes())...)...)...)...)...)...)

	var retHash [32]byte
	copy(retHash[:], crypto.Keccak256(ser)[:])

	return retHash, nil
}
