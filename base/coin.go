package base

import (
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcutil/coinset"
	iwallet "github.com/cpacia/wallet-interface"
)

type Coin struct {
	TxHash       *chainhash.Hash
	TxIndex      uint32
	TxValue      btcutil.Amount
	TxNumConfs   int64
	ScriptPubKey []byte
}

func (c *Coin) Hash() *chainhash.Hash { return c.TxHash }
func (c *Coin) Index() uint32         { return c.TxIndex }
func (c *Coin) Value() btcutil.Amount { return c.TxValue }
func (c *Coin) PkScript() []byte      { return c.ScriptPubKey }
func (c *Coin) NumConfs() int64       { return c.TxNumConfs }
func (c *Coin) ValueAge() int64       { return int64(c.TxValue) * c.TxNumConfs }

func NewCoin(txid iwallet.TransactionID, index uint32, value iwallet.Amount, numConfs int64, addr iwallet.Address) (coinset.Coin, error) {
	ch, err := chainhash.NewHashFromStr(txid.String())
	if err != nil {
		return nil, err
	}

	c := &Coin{
		TxHash:       ch,
		TxIndex:      index,
		TxValue:      btcutil.Amount(value.Int64()),
		TxNumConfs:   numConfs,
		ScriptPubKey: []byte(addr.String()),
	}
	return coinset.Coin(c), nil
}
