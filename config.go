package multiwallet

import (
	"fmt"
	iwallet "github.com/cpacia/wallet-interface"
	"github.com/op/go-logging"
	"path"
)

var (
	DefaultHomeDir = AppDataDir("multiwallet", false)
	DefaultLogDir  = path.Join(DefaultHomeDir, "logs")
)

// Option is a multiwallet option type.
type Option func(*Config) error

type Config struct {
	Wallets    []iwallet.CoinType
	WalletAPIs map[iwallet.CoinType]APIUrls
	UseTestnet bool
	DataDir    string
	LogDir     string
	LogLevel   logging.Level
}

type APIUrls struct {
	Mainnet string
	Testnet string
}

// Defaults are the default options. This option will be automatically
// prepended to any options you pass to the constructor.
var Defaults = func(cfg *Config) error {
	cfg.Wallets = []iwallet.CoinType{
		iwallet.CtBitcoin,
		iwallet.CtBitcoinCash,
		iwallet.CtLitecoin,
		iwallet.CtZCash,
	}
	cfg.WalletAPIs = map[iwallet.CoinType]APIUrls{
		iwallet.CtBitcoinCash: {
			Mainnet: "bchd.greyh.at:8335",
			Testnet: "bchd-testnet.greyh.at:18335",
		},
		iwallet.CtBitcoin: {
			Mainnet: "https://btc.blockbook.api.openbazaar.org/api",
			Testnet: "https://tbtc.blockbook.api.openbazaar.org/api",
		},
		iwallet.CtLitecoin: {
			Mainnet: "https://ltc.blockbook.api.openbazaar.org/api",
			Testnet: "https://tltc.blockbook.api.openbazaar.org/api",
		},
		iwallet.CtZCash: {
			Mainnet: "https://zec.blockbook.api.openbazaar.org/api",
			Testnet: "https://tzec.blockbook.api.openbazaar.org/api",
		},
		iwallet.CtEthereum: {
			Mainnet: "https://mainnet.infura.io",
			Testnet: "https://rinkeby.infura.io",
		},
	}
	cfg.LogLevel = logging.INFO
	cfg.DataDir = DefaultHomeDir
	cfg.LogDir = DefaultLogDir
	return nil
}

// Apply applies the given options to this Option
func (cfg *Config) Apply(opts ...Option) error {
	for i, opt := range opts {
		if err := opt(cfg); err != nil {
			return fmt.Errorf("multiwallet option %d failed: %s", i, err)
		}
	}
	return nil
}

// DataDir configures the multiwallet to use the provided data directory
//
// Defaults to a multiwallet directory inside the os-specific home directory.
func DataDir(dataDir string) Option {
	return func(cfg *Config) error {
		cfg.DataDir = dataDir
		return nil
	}
}

// LogDir configures the multiwallet to use the provided log directory
//
// Defaults to a log directory inside the default home directory.
func LogDir(logDir string) Option {
	return func(cfg *Config) error {
		cfg.LogDir = logDir
		return nil
	}
}

// Wallets configures the multiwallet to use the provided wallets.
//
// Defaults to all implemented wallets.
func Wallets(wallets []iwallet.CoinType) Option {
	return func(cfg *Config) error {
		cfg.Wallets = wallets
		return nil
	}
}

// WalletAPIs configures the multiwallet to use the provided wallet API urls.
// The provided map will override existing config options. If the map does not
// contain a specific key, it will not override the default.
//
// Defaults to all default APIs.
func WalletAPIs(apis map[iwallet.CoinType]APIUrls) Option {
	return func(cfg *Config) error {
		for ct, api := range apis {
			cfg.WalletAPIs[ct] = api
		}
		return nil
	}
}

// LogLevel sets the log level for the wallet.
//
// Defaults to INFO.
func LogLevel(level logging.Level) Option {
	return func(cfg *Config) error {
		cfg.LogLevel = level
		return nil
	}
}
