package ethclient

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/cenkalti/backoff"
	"github.com/cpacia/proxyclient"
	iwallet "github.com/cpacia/wallet-interface"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/nanmu42/etherscan-api"
	"io/ioutil"
	"math/big"
	"net/http"
	"strings"
	"time"
)

// EthClient represents the eth client
type EthClient struct {
	*ethclient.Client
	eClient *etherscan.Client
	url     string
}

// NewEthClient returns a new eth client
func NewEthClient(url string) (*EthClient, error) {
	var econn *etherscan.Client
	if strings.Contains(url, "rinkeby") {
		econn = etherscan.New(etherscan.Rinkby, "your API key")
	} else if strings.Contains(url, "ropsten") {
		econn = etherscan.New(etherscan.Ropsten, "your API key")
	} else {
		econn = etherscan.New(etherscan.Mainnet, "your API key")
	}

	conn, err := rpc.DialHTTPWithClient(url, proxyclient.NewHttpClient())
	if err != nil {
		return nil, err
	}

	return &EthClient{
		Client:  ethclient.NewClient(conn),
		eClient: econn,
		url:     url,
	}, nil

}

// Broadcast sends the transaction to the network and waits for confirmation it succeeded.
func (client *EthClient) Broadcast(signedTx *types.Transaction) error {
	if err := client.SendTransaction(context.Background(), signedTx); err != nil {
		return err
	}

	bo := backoff.NewExponentialBackOff()
	bo.MaxElapsedTime = time.Second * 30
	for {
		rcpt, err := client.TransactionReceipt(context.Background(), signedTx.Hash())
		if err != nil {
			next := bo.NextBackOff()
			if next == backoff.Stop {
				return errors.New("error querying for transaction receipt")
			}
			<-time.After(next)
			continue
		}
		if rcpt.Status <= 0 {
			return errors.New("transaction failed")
		}
		return nil
	}
}

// GetBalance - returns the balance for this account
func (client *EthClient) GetBalance(destAccount common.Address) (*big.Int, error) {
	return client.BalanceAt(context.Background(), destAccount, nil)
}

// GetUnconfirmedBalance - returns the unconfirmed balance for this account
func (client *EthClient) GetUnconfirmedBalance(destAccount common.Address) (*big.Int, error) {
	return client.PendingBalanceAt(context.Background(), destAccount)
}

// GetTransaction - returns a eth txn for the specified hash
func (client *EthClient) GetTransaction(hash common.Hash) (*types.Transaction, bool, error) {
	return client.TransactionByHash(context.Background(), hash)
}

// GetBlockchainInfo returns the info for the best block in the chain.
func (client *EthClient) GetBlockchainInfo() (iwallet.BlockInfo, error) {
	header, err := client.HeaderByNumber(context.Background(), nil)
	if err != nil {
		return iwallet.BlockInfo{}, err
	}

	return iwallet.BlockInfo{
		BlockID: iwallet.BlockID(header.Hash().String()),
		Height: uint64(header.Number.Int64()),
		BlockTime: time.Unix(int64(header.Time), 0),
		PrevBlock: iwallet.BlockID(header.ParentHash.String()),
	}, nil
}

// EstimateTxnGas - returns estimated gas
func (client *EthClient) EstimateTxnGas(from, to common.Address, value *big.Int) (*big.Int, error) {
	gas := big.NewInt(0)
	if !(common.IsHexAddress(from.String()) && common.IsHexAddress(to.String())) {
		return gas, errors.New("invalid address")
	}

	gasPrice, err := client.SuggestGasPrice(context.Background())
	if err != nil {
		return gas, err
	}
	msg := ethereum.CallMsg{From: from, To: &to, Value: value}
	gasLimit, err := client.EstimateGas(context.Background(), msg)
	if err != nil {
		return gas, err
	}
	return gas.Mul(big.NewInt(int64(gasLimit)), gasPrice), nil
}

// EstimateGasSpend - returns estimated gas
func (client *EthClient) EstimateGasSpend(from common.Address, value *big.Int) (*big.Int, error) {
	gas := big.NewInt(0)
	gasPrice, err := client.SuggestGasPrice(context.Background())
	if err != nil {
		return gas, err
	}
	msg := ethereum.CallMsg{From: from, Value: value}
	gasLimit, err := client.EstimateGas(context.Background(), msg)
	if err != nil {
		return gas, err
	}
	return gas.Mul(big.NewInt(int64(gasLimit)), gasPrice), nil
}

// EthGasStationData represents ethgasstation api data
// https://ethgasstation.info/json/ethgasAPI.json
// {"average": 20.0, "fastestWait": 0.4, "fastWait": 0.4, "fast": 200.0,
// "safeLowWait": 10.6, "blockNum": 6684733, "avgWait": 2.0,
// "block_time": 13.056701030927835, "speed": 0.7529715304081577,
// "fastest": 410.0, "safeLow": 17.0}
type EthGasStationData struct {
	Average     float64 `json:"average"`
	FastestWait float64 `json:"fastestWait"`
	FastWait    float64 `json:"fastWeight"`
	Fast        float64 `json:"Fast"`
	SafeLowWait float64 `json:"safeLowWait"`
	BlockNum    int64   `json:"blockNum"`
	AvgWait     float64 `json:"avgWait"`
	BlockTime   float64 `json:"block_time"`
	Speed       float64 `json:"speed"`
	Fastest     float64 `json:"fastest"`
	SafeLow     float64 `json:"safeLow"`
}

// GetEthGasStationEstimate get the latest data
// from https://ethgasstation.info/json/ethgasAPI.json
func (client *EthClient) GetEthGasStationEstimate() (*EthGasStationData, error) {
	res, err := http.Get("https://ethgasstation.info/json/ethgasAPI.json")
	if err != nil {
		return nil, err
	}
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	var s = new(EthGasStationData)
	err = json.Unmarshal(body, &s)
	if err != nil {
		return nil, err
	}
	return s, nil
}
