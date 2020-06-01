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
	cache       map[string]apiResponse
	lastQueried time.Time
	mtx         sync.Mutex
}

type apiResponse struct {
	Last float64 `json:"last"`
}

// NewDefaultExchangeRateProvider returns a new default ExchangeRateProvider.
func NewDefaultExchangeRateProvider(apiURL string) ExchangeRateProvider {
	return &DefaultExchangeRateProvider{
		client:      proxyclient.NewHttpClient(),
		apiEndpoint: apiURL,
		mtx:         sync.Mutex{},
		cache:       make(map[string]apiResponse),
	}
}

// GetUSDRate returns the USD exchange rate for the given coin.
func (erp *DefaultExchangeRateProvider) GetUSDRate(coinType iwallet.CoinType) (iwallet.Amount, error) {
	erp.mtx.Lock()
	defer erp.mtx.Unlock()

	feeMap := make(map[string]apiResponse)
	if erp.lastQueried.Add(time.Minute * 10).After(time.Now()) {
		feeMap = erp.cache
	} else {
		resp, err := erp.client.Get(erp.apiEndpoint)
		if err != nil {
			return iwallet.NewAmount(0), nil
		}
		if err := json.NewDecoder(resp.Body).Decode(&feeMap); err != nil {
			return iwallet.NewAmount(0), nil
		}
	}

	usdRate, ok := feeMap["USD"]
	if !ok {
		return iwallet.NewAmount(0), errors.New("rating unavailable")
	}

	erp.cache = feeMap
	erp.lastQueried = time.Now()

	switch coinType {
	case iwallet.CtBitcoin:
		return iwallet.NewAmount(uint64(usdRate.Last) * 100), nil
	case iwallet.CtBitcoinCash:
		bchRate, ok := feeMap["BCH"]
		if !ok {
			return iwallet.NewAmount(0), errors.New("rating unavailable")
		}
		return iwallet.NewAmount(uint64(usdRate.Last) * 100).Div(iwallet.NewAmount(uint64(bchRate.Last) * 100)), nil
	case iwallet.CtLitecoin:
		ltcRate, ok := feeMap["LTC"]
		if !ok {
			return iwallet.NewAmount(0), errors.New("rating unavailable")
		}
		return iwallet.NewAmount(uint64(usdRate.Last) * 100).Div(iwallet.NewAmount(uint64(ltcRate.Last) * 100)), nil
	case iwallet.CtZCash:
		zecRate, ok := feeMap["ZEC"]
		if !ok {
			return iwallet.NewAmount(0), errors.New("rating unavailable")
		}
		return iwallet.NewAmount(uint64(usdRate.Last) * 100).Div(iwallet.NewAmount(uint64(zecRate.Last) * 100)), nil
	case iwallet.CtEthereum:
		ethRate, ok := feeMap["ETH"]
		if !ok {
			return iwallet.NewAmount(0), errors.New("rating unavailable")
		}
		return iwallet.NewAmount(uint64(usdRate.Last) * 100).Div(iwallet.NewAmount(uint64(ethRate.Last) * 100)), nil
	}
	return iwallet.NewAmount(0), errors.New("unknown cointype")
}
