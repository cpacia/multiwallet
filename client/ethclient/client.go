package ethclient

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/cenkalti/backoff"
	"github.com/cpacia/multiwallet/base"
	"github.com/cpacia/proxyclient"
	iwallet "github.com/cpacia/wallet-interface"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/nanmu42/etherscan-api"
	"io/ioutil"
	"math/big"
	"math/rand"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// EscrowABI is the input ABI used to generate the binding from.
const EscrowABI = "[{\"constant\":false,\"inputs\":[{\"name\":\"buyer\",\"type\":\"address\"},{\"name\":\"seller\",\"type\":\"address\"},{\"name\":\"moderator\",\"type\":\"address\"},{\"name\":\"threshold\",\"type\":\"uint8\"},{\"name\":\"timeoutHours\",\"type\":\"uint32\"},{\"name\":\"scriptHash\",\"type\":\"bytes32\"},{\"name\":\"uniqueId\",\"type\":\"bytes20\"}],\"name\":\"addTransaction\",\"outputs\":[],\"payable\":true,\"stateMutability\":\"payable\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"scriptHash\",\"type\":\"bytes32\"}],\"name\":\"addFundsToTransaction\",\"outputs\":[],\"payable\":true,\"stateMutability\":\"payable\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"uniqueId\",\"type\":\"bytes20\"},{\"name\":\"threshold\",\"type\":\"uint8\"},{\"name\":\"timeoutHours\",\"type\":\"uint32\"},{\"name\":\"buyer\",\"type\":\"address\"},{\"name\":\"seller\",\"type\":\"address\"},{\"name\":\"moderator\",\"type\":\"address\"},{\"name\":\"tokenAddress\",\"type\":\"address\"}],\"name\":\"calculateRedeemScriptHash\",\"outputs\":[{\"name\":\"hash\",\"type\":\"bytes32\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"buyer\",\"type\":\"address\"},{\"name\":\"seller\",\"type\":\"address\"},{\"name\":\"moderator\",\"type\":\"address\"},{\"name\":\"threshold\",\"type\":\"uint8\"},{\"name\":\"timeoutHours\",\"type\":\"uint32\"},{\"name\":\"scriptHash\",\"type\":\"bytes32\"},{\"name\":\"value\",\"type\":\"uint256\"},{\"name\":\"uniqueId\",\"type\":\"bytes20\"},{\"name\":\"tokenAddress\",\"type\":\"address\"}],\"name\":\"addTokenTransaction\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"\",\"type\":\"bytes32\"}],\"name\":\"transactions\",\"outputs\":[{\"name\":\"scriptHash\",\"type\":\"bytes32\"},{\"name\":\"value\",\"type\":\"uint256\"},{\"name\":\"lastModified\",\"type\":\"uint256\"},{\"name\":\"status\",\"type\":\"uint8\"},{\"name\":\"transactionType\",\"type\":\"uint8\"},{\"name\":\"threshold\",\"type\":\"uint8\"},{\"name\":\"timeoutHours\",\"type\":\"uint32\"},{\"name\":\"buyer\",\"type\":\"address\"},{\"name\":\"seller\",\"type\":\"address\"},{\"name\":\"tokenAddress\",\"type\":\"address\"},{\"name\":\"moderator\",\"type\":\"address\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"scriptHash\",\"type\":\"bytes32\"},{\"name\":\"beneficiary\",\"type\":\"address\"}],\"name\":\"checkBeneficiary\",\"outputs\":[{\"name\":\"check\",\"type\":\"bool\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"scriptHash\",\"type\":\"bytes32\"},{\"name\":\"value\",\"type\":\"uint256\"}],\"name\":\"addTokensToTransaction\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"transactionCount\",\"outputs\":[{\"name\":\"\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"partyAddress\",\"type\":\"address\"}],\"name\":\"getAllTransactionsForParty\",\"outputs\":[{\"name\":\"scriptHashes\",\"type\":\"bytes32[]\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"sigV\",\"type\":\"uint8[]\"},{\"name\":\"sigR\",\"type\":\"bytes32[]\"},{\"name\":\"sigS\",\"type\":\"bytes32[]\"},{\"name\":\"scriptHash\",\"type\":\"bytes32\"},{\"name\":\"destinations\",\"type\":\"address[]\"},{\"name\":\"amounts\",\"type\":\"uint256[]\"}],\"name\":\"execute\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"scriptHash\",\"type\":\"bytes32\"},{\"name\":\"party\",\"type\":\"address\"}],\"name\":\"checkVote\",\"outputs\":[{\"name\":\"vote\",\"type\":\"bool\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"\",\"type\":\"address\"},{\"name\":\"\",\"type\":\"uint256\"}],\"name\":\"partyVsTransaction\",\"outputs\":[{\"name\":\"\",\"type\":\"bytes32\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":false,\"name\":\"scriptHash\",\"type\":\"bytes32\"},{\"indexed\":false,\"name\":\"destinations\",\"type\":\"address[]\"},{\"indexed\":false,\"name\":\"amounts\",\"type\":\"uint256[]\"}],\"name\":\"Executed\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":false,\"name\":\"scriptHash\",\"type\":\"bytes32\"},{\"indexed\":true,\"name\":\"from\",\"type\":\"address\"},{\"indexed\":false,\"name\":\"valueAdded\",\"type\":\"uint256\"}],\"name\":\"FundAdded\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":false,\"name\":\"scriptHash\",\"type\":\"bytes32\"},{\"indexed\":true,\"name\":\"from\",\"type\":\"address\"},{\"indexed\":false,\"name\":\"value\",\"type\":\"uint256\"}],\"name\":\"Funded\",\"type\":\"event\"}]=======openzeppelin-solidity/contracts/math/SafeMath.sol:SafeMath=======[]=======token/ITokenContract.sol:ITokenContract=======[{\"constant\":false,\"inputs\":[{\"name\":\"_from\",\"type\":\"address\"},{\"name\":\"_to\",\"type\":\"address\"},{\"name\":\"_amount\",\"type\":\"uint256\"}],\"name\":\"transferFrom\",\"outputs\":[{\"name\":\"success\",\"type\":\"bool\"}],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"_owner\",\"type\":\"address\"}],\"name\":\"balanceOf\",\"outputs\":[{\"name\":\"balance\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"_to\",\"type\":\"address\"},{\"name\":\"_amount\",\"type\":\"uint256\"}],\"name\":\"transfer\",\"outputs\":[{\"name\":\"success\",\"type\":\"bool\"}],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"}]"

// EthClient represents the eth client
type EthClient struct {
	RPC                *ethclient.Client
	WS                 *ethclient.Client
	createRegistryFunc func(client *ethclient.Client) (*common.Address, error)
	contractAddr       *common.Address
	url                string
	httpClient         *http.Client
	subMtx             sync.Mutex
	started            uint32
	shutdown           chan struct{}
	txSubs             map[int32]*base.TransactionSubscription
	blockSubs          map[int32]*base.BlockSubscription
}

// NewEthClient returns a new eth client
func NewEthClient(url string, createRegistry func(client *ethclient.Client) (*common.Address, error)) (*EthClient, error) {
	return &EthClient{
		url:                url,
		createRegistryFunc: createRegistry,
		httpClient:         proxyclient.NewHttpClient(),
		shutdown:           make(chan struct{}),
		subMtx:             sync.Mutex{},
		txSubs:             make(map[int32]*base.TransactionSubscription),
		blockSubs:          make(map[int32]*base.BlockSubscription),
	}, nil
}

func (c *EthClient) GetBlockchainInfo() (iwallet.BlockInfo, error) {
	if atomic.LoadUint32(&c.started) == 0 {
		return iwallet.BlockInfo{}, errors.New("rpc client not connected")
	}
	header, err := c.RPC.HeaderByNumber(context.Background(), nil)
	if err != nil {
		return iwallet.BlockInfo{}, err
	}

	return iwallet.BlockInfo{
		BlockID:   iwallet.BlockID(header.Hash().String()),
		Height:    uint64(header.Number.Int64()),
		BlockTime: time.Unix(int64(header.Time), 0),
		PrevBlock: iwallet.BlockID(header.ParentHash.String()),
	}, nil
}

func (c *EthClient) GetAddressTransactions(addr iwallet.Address, fromHeight uint64) ([]iwallet.Transaction, error) {
	type transactionsResult struct {
		Result []jsonTransaction `json:"result"`
	}

	network := etherscan.Rinkby
	if strings.Contains(c.url, "mainnet") {
		network = etherscan.Mainnet
	}
	resp, err := c.httpClient.Get(fmt.Sprintf("https://%s.etherscan.io/api?module=account&action=txlist&address=%s&sort=desc&startblock=%d", network, addr.String(), fromHeight))
	if err != nil {
		return nil, err
	}

	decoder := json.NewDecoder(resp.Body)

	var result transactionsResult
	if err := decoder.Decode(&result); err != nil {
		return nil, err
	}

	var txs []iwallet.Transaction
	for _, tx := range result.Result {
		txn, err := c.buildTransactionFromJSON(&tx)
		if err != nil {
			return nil, err
		}
		txs = append(txs, txn)
	}

	return txs, nil
}

func (c *EthClient) GetTransaction(id iwallet.TransactionID) (iwallet.Transaction, error) {
	type transactionsResult struct {
		Result jsonTransaction `json:"result"`
	}
	network := etherscan.Rinkby
	if strings.Contains(c.url, "mainnet") {
		network = etherscan.Mainnet
	}
	resp, err := c.httpClient.Get(fmt.Sprintf("https://%s.etherscan.io/api?module=proxy&action=eth_getTransactionByHash&txhash=%s", network, id.String()))
	if err != nil {
		return iwallet.Transaction{}, err
	}

	decoder := json.NewDecoder(resp.Body)

	var result transactionsResult
	if err := decoder.Decode(&result); err != nil {
		return iwallet.Transaction{}, err
	}

	return c.buildTransactionFromJSON(&result.Result)
}

func (c *EthClient) IsBlockInMainChain(block iwallet.BlockInfo) (bool, error) {
	if atomic.LoadUint32(&c.started) == 0 {
		return false, errors.New("rpc client not connected")
	}
	header, err := c.RPC.HeaderByNumber(context.Background(), big.NewInt(int64(block.Height)))
	if err != nil {
		return false, err
	}
	return header.Hash().String() == block.BlockID.String(), nil
}

func (c *EthClient) SubscribeTransactions(addrs []iwallet.Address) (*base.TransactionSubscription, error) {
	if atomic.LoadUint32(&c.started) == 0 {
		return nil, errors.New("websocket client not connected")
	}

	c.subMtx.Lock()
	defer c.subMtx.Unlock()

	sub := &base.TransactionSubscription{
		Out: make(chan iwallet.Transaction),
	}

	id := rand.Int31()
	c.txSubs[id] = sub

	cAddrs := make([]common.Address, 0, len(addrs))
	for _, addr := range addrs {
		cAddrs = append(cAddrs, common.HexToAddress(addr.String()))
	}

	ch := make(chan types.Log)
	ethSub, err := c.WS.SubscribeFilterLogs(context.Background(), ethereum.FilterQuery{Addresses: cAddrs}, ch)
	if err != nil {
		return nil, err
	}

	sub.Close = func() {
		c.subMtx.Lock()
		delete(c.txSubs, id)
		c.subMtx.Unlock()
		ethSub.Unsubscribe()
		close(sub.Out)
	}
	go func() {
		for {
			select {
			case log := <-ch:
				tx, err := c.GetTransaction(iwallet.TransactionID(log.TxHash.String()))
				if err != nil {
					continue
				}
				sub.Out <- tx
			case <-c.shutdown:
				return
			}
		}
	}()

	return sub, nil
}

func (c *EthClient) SubscribeBlocks() (*base.BlockSubscription, error) {
	if atomic.LoadUint32(&c.started) == 0 {
		return nil, errors.New("websocket client not connected")
	}

	c.subMtx.Lock()
	defer c.subMtx.Unlock()

	sub := &base.BlockSubscription{
		Out: make(chan iwallet.BlockInfo),
	}

	id := rand.Int31()
	c.blockSubs[id] = sub

	ch := make(chan *types.Header)
	ethSub, err := c.WS.SubscribeNewHead(context.Background(), ch)
	if err != nil {
		return nil, err
	}

	sub.Close = func() {
		c.subMtx.Lock()
		delete(c.blockSubs, id)
		c.subMtx.Unlock()
		ethSub.Unsubscribe()
		close(sub.Out)
	}
	go func() {
		for {
			select {
			case header := <-ch:
				if header == nil {
					return
				}
				sub.Out <- iwallet.BlockInfo{
					BlockID:   iwallet.BlockID(header.Hash().String()),
					PrevBlock: iwallet.BlockID(header.ParentHash.String()),
					BlockTime: time.Unix(int64(header.Time), 0),
					Height:    header.Number.Uint64(),
				}
			case <-c.shutdown:
				return
			}
		}
	}()

	return sub, nil
}

func (c *EthClient) Broadcast(serializedTx []byte) error {
	if atomic.LoadUint32(&c.started) == 0 {
		return errors.New("rpc client not connected")
	}
	signedTx := new(types.Transaction)

	if err := signedTx.UnmarshalJSON(serializedTx); err != nil {
		return err
	}

	if err := c.RPC.SendTransaction(context.Background(), signedTx); err != nil {
		return err
	}

	bo := backoff.NewExponentialBackOff()
	bo.MaxElapsedTime = time.Second * 30
	for {
		rcpt, err := c.RPC.TransactionReceipt(context.Background(), signedTx.Hash())
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

func (c *EthClient) Close() error {
	close(c.shutdown)
	if c.RPC != nil {
		c.RPC.Close()
	}
	if c.WS != nil {
		c.WS.Close()
	}
	return nil
}

// EstimateTxnGas - returns estimated gas
func (c *EthClient) EstimateTxnGas(from, to common.Address, value *big.Int) (*big.Int, error) {
	if atomic.LoadUint32(&c.started) == 0 {
		return nil, errors.New("rpc client not connected")
	}
	gas := big.NewInt(0)
	if !(common.IsHexAddress(from.String()) && common.IsHexAddress(to.String())) {
		return gas, errors.New("invalid address")
	}

	gasPrice, err := c.RPC.SuggestGasPrice(context.Background())
	if err != nil {
		return gas, err
	}
	msg := ethereum.CallMsg{From: from, To: &to, Value: value}
	gasLimit, err := c.RPC.EstimateGas(context.Background(), msg)
	if err != nil {
		return gas, err
	}
	return gas.Mul(big.NewInt(int64(gasLimit)), gasPrice), nil
}

// EstimateGasSpend - returns estimated gas
func (c *EthClient) EstimateGasSpend(from common.Address, value *big.Int) (*big.Int, error) {
	if atomic.LoadUint32(&c.started) == 0 {
		return nil, errors.New("rpc client not connected")
	}
	gas := big.NewInt(0)
	gasPrice, err := c.RPC.SuggestGasPrice(context.Background())
	if err != nil {
		return gas, err
	}
	msg := ethereum.CallMsg{From: from, Value: value}
	gasLimit, err := c.RPC.EstimateGas(context.Background(), msg)
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
func (c *EthClient) GetEthGasStationEstimate() (*EthGasStationData, error) {
	res, err := c.httpClient.Get("https://ethgasstation.info/json/ethgasAPI.json")
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

func (c *EthClient) Open() error {
	conn, err := rpc.DialHTTPWithClient(c.url, proxyclient.NewHttpClient())
	if err != nil {
		return err
	}

	ws, err := rpc.DialWebsocket(context.Background(), strings.Replace(c.url, "https", "wss", 1)+"/ws", "")
	if err != nil {
		conn.Close()
		return err
	}

	rpc := ethclient.NewClient(conn)

	contractAddr, err := c.createRegistryFunc(rpc)
	if err != nil {
		ws.Close()
		conn.Close()
		return err
	}

	c.contractAddr = contractAddr
	c.RPC = rpc
	c.WS = ethclient.NewClient(ws)

	atomic.AddUint32(&c.started, 1)
	return nil
}

type jsonTransaction struct {
	BlockNumber   string `json:"blockNumber"`
	Timestamp     string `json:"timeStamp"`
	Hash          string `json:"hash"`
	BlockHash     string `json:"blockHash"`
	From          string `json:"from"`
	To            string `json:"to"`
	Value         string `json:"value"`
	Confirmations string `json:"confirmations"`
	Input         string `json:"input"`
}

func (c *EthClient) buildTransactionFromJSON(tx *jsonTransaction) (iwallet.Transaction, error) {
	fromAddr := iwallet.NewAddress(tx.From, iwallet.CtEthereum)
	toAddr := iwallet.NewAddress(tx.To, iwallet.CtEthereum)
	ts := time.Now()
	if tx.Timestamp != "" {
		ts = time.Unix(iwallet.NewAmount(tx.Timestamp).Int64(), 0)
	}
	var val iwallet.Amount
	_, ok := new(big.Int).SetString(tx.Value, 10)
	if ok {
		val = iwallet.NewAmount(tx.Value)
	} else {
		valBytes, err := hex.DecodeString(strings.TrimPrefix(tx.Value, "0x"))
		if err != nil {
			return iwallet.Transaction{}, err
		}
		val = iwallet.NewAmount(new(big.Int).SetBytes(valBytes))
	}

	var height iwallet.Amount
	_, ok = new(big.Int).SetString(tx.BlockNumber, 10)
	if ok {
		height = iwallet.NewAmount(tx.BlockNumber)
	} else {
		heightBytes, err := hex.DecodeString(strings.TrimPrefix(tx.BlockNumber, "0x"))
		if err != nil {
			return iwallet.Transaction{}, err
		}
		height = iwallet.NewAmount(new(big.Int).SetBytes(heightBytes))
	}

	txn := iwallet.Transaction{
		ID:        iwallet.TransactionID(tx.Hash),
		Value:     val,
		Timestamp: ts,
		Height:    height.Uint64(),
	}
	if tx.BlockHash != "" {
		txn.BlockInfo = &iwallet.BlockInfo{
			BlockID:   iwallet.BlockID(tx.BlockHash),
			Height:    height.Uint64(),
			BlockTime: ts,
		}
	}

	txidBytes, err := hex.DecodeString(strings.TrimPrefix(tx.Hash, "0x"))
	if err != nil {
		return iwallet.Transaction{}, err
	}

	var (
		data []byte
	)
	if len(tx.Input) > 0 {
		data, err = hex.DecodeString(strings.TrimPrefix(tx.Input, "0x"))
		if err != nil {
			return iwallet.Transaction{}, err
		}
	}

	if c.contractAddr != nil && *c.contractAddr == common.HexToAddress(tx.To) {
		parsed, err := abi.JSON(strings.NewReader(EscrowABI))
		if err != nil {
			return iwallet.Transaction{}, err
		}
		fromVal := val
		if bytes.HasPrefix(data, []byte{0xe4, 0xec, 0x8b, 0x00}) { // execute
			method, err := parsed.MethodById([]byte{0xe4, 0xec, 0x8b, 0x00})
			if err != nil {
				return iwallet.Transaction{}, err
			}
			m := make(map[string]interface{})
			err = method.Inputs.UnpackIntoMap(m, data[4:])
			if err != nil {
				return iwallet.Transaction{}, err
			}
			scriptHash := m["scriptHash"].([32]byte)
			fromAddr = iwallet.NewAddress("0x"+hex.EncodeToString(scriptHash[:]), iwallet.CtEthereum)
			amts := m["amounts"].([]*big.Int)
			total := iwallet.NewAmount(0)
			for i, destination := range m["destinations"].([]common.Address) {
				idx := make([]byte, 4)
				binary.BigEndian.PutUint32(idx, uint32(i))
				txn.To = append(txn.To, iwallet.SpendInfo{
					ID:      append(txidBytes, idx...),
					Address: iwallet.NewAddress(destination.String(), iwallet.CtEthereum),
					Amount:  iwallet.NewAmount(amts[i]),
				})
				total = total.Add(iwallet.NewAmount(amts[i]))
			}
			fromVal = total

		} else if bytes.HasPrefix(data, []byte{0x23, 0xb6, 0xfd, 0x3f}) { // addTransaction
			method, err := parsed.MethodById([]byte{0x23, 0xb6, 0xfd, 0x3f})
			if err != nil {
				return iwallet.Transaction{}, err
			}
			m := make(map[string]interface{})
			err = method.Inputs.UnpackIntoMap(m, data[4:])
			if err != nil {
				return iwallet.Transaction{}, err
			}

			scriptHash := m["scriptHash"].([32]byte)
			txn.To = []iwallet.SpendInfo{
				{
					ID:      append(txidBytes, []byte{0x00, 0x00, 0x00, 0x00}...),
					Address: iwallet.NewAddress("0x"+hex.EncodeToString(scriptHash[:]), iwallet.CtEthereum),
					Amount:  val,
				},
			}
		}

		txn.From = []iwallet.SpendInfo{
			{
				Address: iwallet.NewAddress(fromAddr.String(), iwallet.CtEthereum),
				Amount:  fromVal,
			},
		}
	} else {
		if len(data) > 0 {
			toAddr = iwallet.NewAddress("0x"+hex.EncodeToString(data), iwallet.CtEthereum)
		}
		txn.From = []iwallet.SpendInfo{
			{
				Address: iwallet.NewAddress(fromAddr.String(), iwallet.CtEthereum),
				Amount:  val,
			},
		}
		txn.To = []iwallet.SpendInfo{
			{
				ID:      append(txidBytes, []byte{0x00, 0x00, 0x00, 0x00}...),
				Address: iwallet.NewAddress(toAddr.String(), iwallet.CtEthereum),
				Amount:  val,
			},
		}
	}
	return txn, nil
}
