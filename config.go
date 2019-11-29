package multiwallet

import (
	iwallet "github.com/cpacia/wallet-interface"
)

type Config struct {
	Wallets    []iwallet.CoinType
	UseTestnet bool
	DataDir    string
	LogDir     string
	LogLevel   string
}
