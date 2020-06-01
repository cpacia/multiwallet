package base

import (
	"encoding/json"
	"errors"
	"github.com/cpacia/proxyclient"
	iwallet "github.com/cpacia/wallet-interface"
	"net/http"
	"sync"
	"time"
)

// ExchangeRateProvider is an interface that is used by the ExchangeRateFeeProvider to
// calculate the fee to target a given exchange rate.
type ExchangeRateProvider interface {
	// GetUSDRate returns the USD exchange rate for the given coin.
	GetUSDRate(coinType iwallet.CoinType) (iwallet.Amount, error)
}

// DefaultExchangeRateProvider is a basic implementation of the exchange rate
// provider which uses the OpenBazaar api.
type DefaultExchangeRateProvider struct {
	apiEndpoint string
	client      *http.Client
	cache       iwallet.Amount
	lastQueried time.Time
	mtx         sync.Mutex
}

// NewDefaultExchangeRateProvider returns a new default ExchangeRateProvider.
func NewDefaultExchangeRateProvider(apiURL string) ExchangeRateProvider {
	return &DefaultExchangeRateProvider{
		client:      proxyclient.NewHttpClient(),
		apiEndpoint: apiURL,
		mtx:         sync.Mutex{},
	}
}

// GetUSDRate returns the USD exchange rate for the given coin.
func (erp *DefaultExchangeRateProvider) GetUSDRate(coinType iwallet.CoinType) (iwallet.Amount, error) {
	erp.mtx.Lock()
	defer erp.mtx.Unlock()

	if erp.lastQueried.Add(time.Minute * 10).Before(time.Now()) {
		return erp.cache, nil
	}

	type apiResponse struct {
		Last float64 `json:"last"`
	}

	resp, err := erp.client.Get(erp.apiEndpoint)
	if err != nil {
		return iwallet.NewAmount(0), nil
	}

	feeMap := make(map[string]apiResponse)

	if err := json.NewDecoder(resp.Body).Decode(&feeMap); err != nil {
		return iwallet.NewAmount(0), nil
	}

	usdRate, ok := feeMap["USD"]
	if !ok {
		return iwallet.NewAmount(0), errors.New("rating unavailable")
	}

	erp.cache = iwallet.NewAmount(usdRate.Last * 100)
	erp.lastQueried = time.Now()

	switch coinType {
	case iwallet.CtBitcoin:
		return erp.cache, nil
	case iwallet.CtBitcoinCash:
		bchRate, ok := feeMap["BCH"]
		if !ok {
			return iwallet.NewAmount(0), errors.New("rating unavailable")
		}
		return erp.cache.Div(iwallet.NewAmount(bchRate.Last)), nil
	case iwallet.CtLitecoin:
		ltcRate, ok := feeMap["LTC"]
		if !ok {
			return iwallet.NewAmount(0), errors.New("rating unavailable")
		}
		return erp.cache.Div(iwallet.NewAmount(ltcRate.Last)), nil
	case iwallet.CtZCash:
		zecRate, ok := feeMap["ZEC"]
		if !ok {
			return iwallet.NewAmount(0), errors.New("rating unavailable")
		}
		return erp.cache.Div(iwallet.NewAmount(zecRate.Last)), nil
	case iwallet.CtEthereum:
		ethRate, ok := feeMap["ETH"]
		if !ok {
			return iwallet.NewAmount(0), errors.New("rating unavailable")
		}
		return erp.cache.Div(iwallet.NewAmount(ethRate.Last)), nil
	}
	return iwallet.NewAmount(0), errors.New("unknown cointype")
}
