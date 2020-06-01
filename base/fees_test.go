package base

import (
	iwallet "github.com/cpacia/wallet-interface"
	"github.com/jarcoal/httpmock"
	"testing"
)

func TestHardCodedFeeProvider_GetFee(t *testing.T) {
	tests := []struct {
		feeLevel iwallet.FeeLevel
		expected iwallet.Amount
	}{
		{
			feeLevel: iwallet.FlPriority,
			expected: iwallet.NewAmount(50),
		},
		{
			feeLevel: iwallet.FlNormal,
			expected: iwallet.NewAmount(40),
		},
		{
			feeLevel: iwallet.FlEconomic,
			expected: iwallet.NewAmount(30),
		},
		{
			feeLevel: iwallet.FLSuperEconomic,
			expected: iwallet.NewAmount(20),
		},
		{
			feeLevel: iwallet.FeeLevel(100),
			expected: iwallet.NewAmount(100),
		},
	}

	fp := NewHardCodedFeeProvider(iwallet.NewAmount(50), iwallet.NewAmount(40), iwallet.NewAmount(30), iwallet.NewAmount(20))

	for i, test := range tests {
		amt, err := fp.GetFee(test.feeLevel)
		if err != nil {
			t.Fatal(err)
		}
		if amt.Cmp(test.expected) != 0 {
			t.Errorf("Test %d: expected %s, got %s", i, test.expected, amt)
		}
	}
}

func TestAPIFeeProvider_GetFee(t *testing.T) {
	tests := []struct {
		feeLevel iwallet.FeeLevel
		expected iwallet.Amount
	}{
		{
			feeLevel: iwallet.FlPriority,
			expected: iwallet.NewAmount(153),
		},
		{
			feeLevel: iwallet.FlNormal,
			expected: iwallet.NewAmount(102),
		},
		{
			feeLevel: iwallet.FlEconomic,
			expected: iwallet.NewAmount(61),
		},
		{
			feeLevel: iwallet.FLSuperEconomic,
			expected: iwallet.NewAmount(30),
		},
		{
			feeLevel: iwallet.FeeLevel(100),
			expected: iwallet.NewAmount(100),
		},
	}

	url := "https://ticker.openbazaar.org/api"
	httpmock.RegisterResponder("GET", url,
		httpmock.NewStringResponder(200, `{"priority":153,"normal":102,"economic":61,"superEconomic":30}`))

	httpmock.Activate()
	defer httpmock.Deactivate()

	fp := NewAPIFeeProvider(url, iwallet.NewAmount(200))

	for i, test := range tests {
		amt, err := fp.GetFee(test.feeLevel)
		if err != nil {
			t.Fatal(err)
		}
		if amt.Cmp(test.expected) != 0 {
			t.Errorf("Test %d: expected %s, got %s", i, test.expected, amt)
		}
	}
}

func TestExchangeRateFeeProvider_GetFee(t *testing.T) {
	tests := []struct {
		feeLevel iwallet.FeeLevel
		expected iwallet.Amount
	}{
		{
			feeLevel: iwallet.FlPriority,
			expected: iwallet.NewAmount(90),
		},
		{
			feeLevel: iwallet.FlNormal,
			expected: iwallet.NewAmount(54),
		},
		{
			feeLevel: iwallet.FlEconomic,
			expected: iwallet.NewAmount(18),
		},
		{
			feeLevel: iwallet.FLSuperEconomic,
			expected: iwallet.NewAmount(3),
		},
		{
			feeLevel: iwallet.FeeLevel(100),
			expected: iwallet.NewAmount(100),
		},
	}

	url := "https://ticker.openbazaar.org/api"
	erp := NewDefaultExchangeRateProvider(url)

	httpmock.RegisterResponder("GET", url,
		httpmock.NewStringResponder(200, `{"USD":{"ask":9528.50,"bid":9523.20,"last":9525.10,"type":"fiat"},"BCH":{"ask":39.29913,"bid":39.29913,"last":39.29913,"type":"crypto"},"LTC":{"ask":204.71288,"bid":204.71288,"last":204.71288,"type":"crypto"},"ZEC":{"ask":180.27805,"bid":180.27805,"last":180.27805,"type":"crypto"},"ETH":{"ask":40.29592,"bid":40.29592,"last":40.29592,"type":"crypto"}}`))

	httpmock.Activate()
	defer httpmock.Deactivate()

	fp := NewExchangeRateFeeProvider(iwallet.CtBitcoinCash, 8, erp, 226, iwallet.NewAmount(200), 5, 3, 1, .2)

	for i, test := range tests {
		amt, err := fp.GetFee(test.feeLevel)
		if err != nil {
			t.Fatal(err)
		}
		if amt.Cmp(test.expected) != 0 {
			t.Errorf("Test %d: expected %s, got %s", i, test.expected, amt)
		}
	}
}
