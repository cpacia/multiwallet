package multiwallet

import (
	"errors"
	"fmt"
	"github.com/cpacia/multiwallet/base"
	"github.com/cpacia/multiwallet/coins/bitcoin"
	"github.com/cpacia/multiwallet/coins/bitcoincash"
	"github.com/cpacia/multiwallet/coins/litecoin"
	"github.com/cpacia/multiwallet/coins/zcash"
	"github.com/cpacia/multiwallet/database"
	"github.com/cpacia/multiwallet/database/sqlitedb"
	iwallet "github.com/cpacia/wallet-interface"
	"github.com/natefinch/lumberjack"
	"github.com/op/go-logging"
	"os"
	"path"
	"strings"
)

var (
	defaultLogFilename = "multiwallet.log"
	ErrUnsuppertedCoin = errors.New("multiwallet does not contain an implementation for the given coin")
	fileLogFormat      = logging.MustStringFormatter(`%{time:2006-01-02 T15:04:05.000} [%{level}] [%{module}] %{message}`)
	stdoutLogFormat    = logging.MustStringFormatter(`%{color:reset}%{color}%{time:15:04:05} [%{level}] [%{module}] %{message}`)
)

type Multiwallet map[iwallet.CoinType]iwallet.Wallet

func NewMultiwallet(opts ...Option) (Multiwallet, error) {
	var cfg Config
	if err := cfg.Apply(append([]Option{Defaults}, opts...)...); err != nil {
		return nil, err
	}

	logger := logging.MustGetLogger("multiwallet")

	backendStdout := logging.NewLogBackend(os.Stdout, "", 0)
	backendStdoutFormatter := logging.NewBackendFormatter(backendStdout, stdoutLogFormat)

	if cfg.LogDir != "" {
		rotator := &lumberjack.Logger{
			Filename:   path.Join(cfg.LogDir, defaultLogFilename),
			MaxSize:    10, // Megabytes
			MaxBackups: 3,
			MaxAge:     30, // Days
		}

		backendFile := logging.NewLogBackend(rotator, "", 0)
		backendFileFormatter := logging.NewBackendFormatter(backendFile, fileLogFormat)
		leveledBackend := logging.MultiLogger(backendStdoutFormatter, backendFileFormatter)
		leveledBackend.SetLevel(cfg.LogLevel, "")
		logger.SetBackend(leveledBackend)
	} else {
		leveledBackend := logging.AddModuleLevel(backendStdoutFormatter)
		leveledBackend.SetLevel(cfg.LogLevel, "")
		logger.SetBackend(leveledBackend)
	}

	os.MkdirAll(cfg.DataDir, os.ModePerm)
	db, err := sqlitedb.NewSqliteDB(cfg.DataDir)
	if err != nil {
		return nil, err
	}

	if err := database.InitializeDatabase(db); err != nil {
		return nil, err
	}

	multiwallet := make(map[iwallet.CoinType]iwallet.Wallet)
	for _, coinType := range cfg.Wallets {
		switch coinType {
		case iwallet.CtBitcoinCash:
			clientURL := cfg.WalletAPIs[coinType].Mainnet
			if cfg.UseTestnet {
				clientURL = cfg.WalletAPIs[coinType].Testnet
			}
			w, err := bitcoincash.NewBitcoinCashWallet(&base.WalletConfig{
				Logger:               logger,
				DB:                   db,
				ClientURL:            clientURL,
				Testnet:              cfg.UseTestnet,
				ExchangeRateProvider: cfg.ExchangeRateProvider,
			})
			if err != nil {
				return nil, err
			}

			multiwallet[coinType] = w
		case iwallet.CtBitcoin:
			clientURL := cfg.WalletAPIs[coinType].Mainnet
			if cfg.UseTestnet {
				clientURL = cfg.WalletAPIs[coinType].Testnet
			}
			w, err := bitcoin.NewBitcoinWallet(&base.WalletConfig{
				Logger:    logger,
				DB:        db,
				ClientURL: clientURL,
				Testnet:   cfg.UseTestnet,
				FeeURL:    "https://btc.fees.openbazaar.org",
			})
			if err != nil {
				return nil, err
			}

			multiwallet[coinType] = w
		case iwallet.CtLitecoin:
			clientURL := cfg.WalletAPIs[coinType].Mainnet
			if cfg.UseTestnet {
				clientURL = cfg.WalletAPIs[coinType].Testnet
			}
			w, err := litecoin.NewLitecoinWallet(&base.WalletConfig{
				Logger:               logger,
				DB:                   db,
				ClientURL:            clientURL,
				Testnet:              cfg.UseTestnet,
				ExchangeRateProvider: cfg.ExchangeRateProvider,
			})
			if err != nil {
				return nil, err
			}

			multiwallet[coinType] = w
		case iwallet.CtZCash:
			clientURL := cfg.WalletAPIs[coinType].Mainnet
			if cfg.UseTestnet {
				clientURL = cfg.WalletAPIs[coinType].Testnet
			}
			w, err := zcash.NewZCashWallet(&base.WalletConfig{
				Logger:               logger,
				DB:                   db,
				ClientURL:            clientURL,
				Testnet:              cfg.UseTestnet,
				ExchangeRateProvider: cfg.ExchangeRateProvider,
			})
			if err != nil {
				return nil, err
			}

			multiwallet[coinType] = w
		default:
			return nil, fmt.Errorf("a wallet implementation for %s does not exist", coinType.CurrencyCode())
		}
	}

	return multiwallet, nil
}

func (w *Multiwallet) Start() error {
	for _, wallet := range *w {
		if err := wallet.OpenWallet(); err != nil {
			return err
		}
	}
	return nil
}

func (w *Multiwallet) Close() error {
	for _, wallet := range *w {
		if err := wallet.CloseWallet(); err != nil {
			return err
		}
	}
	return nil
}

func (w *Multiwallet) WalletForCurrencyCode(currencyCode string) (iwallet.Wallet, error) {
	for cc, wl := range *w {
		if strings.ToUpper(cc.CurrencyCode()) == strings.ToUpper(currencyCode) || strings.ToUpper(cc.CurrencyCode()) == "T"+strings.ToUpper(currencyCode) {
			return wl, nil
		}
	}
	return nil, ErrUnsuppertedCoin
}
