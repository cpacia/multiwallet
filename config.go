package multiwallet

import (
	"github.com/btcsuite/btcutil/hdkeychain"
	iwallet "github.com/cpacia/wallet-interface"
)

type Config struct {
	Wallets    []*WalletConfig
	UseTestnet bool
	DataDir    string
	LogDir     string
	LogLevel   string
}

type WalletConfig struct {
	CoinType iwallet.CoinType
	XPriv    *hdkeychain.ExtendedKey
}
