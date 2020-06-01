package base

import (
	iwallet "github.com/cpacia/wallet-interface"
	"github.com/jarcoal/httpmock"
	"testing"
)

func TestDefaultExchangeRateProvider_GetUSDRate(t *testing.T) {
	url := "https://ticker.openbazaar.org/api"
	erp := NewDefaultExchangeRateProvider(url)

	httpmock.RegisterResponder("GET", url,
		httpmock.NewStringResponder(200, `{"USD":{"ask":9528.50,"bid":9523.20,"last":9525.10,"type":"fiat"},"BCH":{"ask":39.29913,"bid":39.29913,"last":39.29913,"type":"crypto"},"LTC":{"ask":204.71288,"bid":204.71288,"last":204.71288,"type":"crypto"},"ZEC":{"ask":180.27805,"bid":180.27805,"last":180.27805,"type":"crypto"},"ETH":{"ask":40.29592,"bid":40.29592,"last":40.29592,"type":"crypto"}}`))

	httpmock.Activate()
	defer httpmock.Deactivate()

	rate, err := erp.GetUSDRate(iwallet.CtBitcoin)
	if err != nil {
		t.Fatal(err)
	}
	if rate.Cmp(iwallet.NewAmount(952500)) != 0 {
		t.Errorf("Expected rate %d, got %s", 952500, rate)
	}

	rate, err = erp.GetUSDRate(iwallet.CtBitcoinCash)
	if err != nil {
		t.Fatal(err)
	}
	if rate.Cmp(iwallet.NewAmount(244)) != 0 {
		t.Errorf("Expected rate %d, got %s", 244, rate)
	}

	rate, err = erp.GetUSDRate(iwallet.CtLitecoin)
	if err != nil {
		t.Fatal(err)
	}
	if rate.Cmp(iwallet.NewAmount(46)) != 0 {
		t.Errorf("Expected rate %d, got %s", 46, rate)
	}

	rate, err = erp.GetUSDRate(iwallet.CtZCash)
	if err != nil {
		t.Fatal(err)
	}
	if rate.Cmp(iwallet.NewAmount(52)) != 0 {
		t.Errorf("Expected rate %d, got %s", 52, rate)
	}

	rate, err = erp.GetUSDRate(iwallet.CtEthereum)
	if err != nil {
		t.Fatal(err)
	}
	if rate.Cmp(iwallet.NewAmount(238)) != 0 {
		t.Errorf("Expected rate %d, got %s", 238, rate)
	}

	// Test cache
	httpmock.RegisterResponder("GET", url,
		httpmock.NewStringResponder(200, `{"USD":{"ask":5000.50,"bid":9523.20,"last":9525.10,"type":"fiat"},"BCH":{"ask":39.29913,"bid":39.29913,"last":39.29913,"type":"crypto"},"LTC":{"ask":204.71288,"bid":204.71288,"last":204.71288,"type":"crypto"},"ZEC":{"ask":180.27805,"bid":180.27805,"last":180.27805,"type":"crypto"},"ETH":{"ask":40.29592,"bid":40.29592,"last":40.29592,"type":"crypto"}}`))

	rate, err = erp.GetUSDRate(iwallet.CtBitcoin)
	if err != nil {
		t.Fatal(err)
	}
	if rate.Cmp(iwallet.NewAmount(952500)) != 0 {
		t.Errorf("Expected rate %d, got %s", 952500, rate)
	}
}
