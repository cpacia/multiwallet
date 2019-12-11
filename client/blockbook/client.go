package blockbook

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	gosocketio "github.com/OpenBazaar/golang-socketio"
	"github.com/OpenBazaar/golang-socketio/protocol"
	"github.com/btcsuite/btcutil"
	"github.com/cenkalti/backoff"
	"github.com/cpacia/multiwallet/base"
	iwallet "github.com/cpacia/wallet-interface"
	"io/ioutil"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const RequestTimeout = time.Second * 30

// BlockbookClient is a blockbook client that connects to the blockbook
// server which supports multiple coins.
type BlockbookClient struct {
	client    *http.Client
	socket    *gosocketio.Client
	clientUrl string
	coinType  iwallet.CoinType
	subMtx    sync.Mutex
	shutdown  chan struct{}
	txSubs    map[int32]*base.TransactionSubscription
	blockSubs map[int32]*base.BlockSubscription
}

// NewBlockbookClient returns a new BlockbookClient connected to the provided URL.
func NewBlockbookClient(url string, coinType iwallet.CoinType) (*BlockbookClient, error) {
	url = strings.TrimSuffix(url, "/")
	client := &BlockbookClient{
		client: &http.Client{
			Timeout: RequestTimeout,
		},
		clientUrl: url,
		coinType:  coinType,
		shutdown:  make(chan struct{}),
		subMtx:    sync.Mutex{},
		txSubs:    make(map[int32]*base.TransactionSubscription),
		blockSubs: make(map[int32]*base.BlockSubscription),
	}
	client.connectSocket()
	return client, nil
}

type socketioReq struct {
	Method string        `json:"method"`
	Params []interface{} `json:"params"`
}

func (c *BlockbookClient) GetBlockchainInfo() (iwallet.BlockInfo, error) {
	type Info struct {
		Blockbook struct {
			LastBlockTime time.Time `json:"lastBlockTime"`
		} `json:"blockbook"`
		Backend struct {
			BestHeight int    `json:"blocks"`
			BestHash   string `json:"bestblockhash"`
		} `json:"backend"`
	}

	resp, err := c.client.Get(c.clientUrl)
	if err != nil {
		return iwallet.BlockInfo{}, err
	}

	if resp.StatusCode != http.StatusOK {
		return iwallet.BlockInfo{}, errors.New("incorrect status code")
	}

	decoder := json.NewDecoder(resp.Body)

	var info Info
	if err := decoder.Decode(&info); err != nil {
		return iwallet.BlockInfo{}, err
	}

	type BlockHash struct {
		Hash string `json:"blockHash"`
	}

	resp, err = c.client.Get(c.clientUrl + "/block-index/" + strconv.Itoa(info.Backend.BestHeight-1))
	if err != nil {
		return iwallet.BlockInfo{}, err
	}

	if resp.StatusCode != http.StatusOK {
		return iwallet.BlockInfo{}, errors.New("incorrect status code")
	}

	decoder = json.NewDecoder(resp.Body)

	var prevHash BlockHash
	if err := decoder.Decode(&prevHash); err != nil {
		return iwallet.BlockInfo{}, err
	}

	return iwallet.BlockInfo{
		Height:    uint64(info.Backend.BestHeight),
		BlockID:   iwallet.BlockID(info.Backend.BestHash),
		BlockTime: info.Blockbook.LastBlockTime,
		PrevBlock: iwallet.BlockID(prevHash.Hash),
	}, nil
}

func (c *BlockbookClient) GetAddressTransactions(addr iwallet.Address, fromHeight uint64) ([]iwallet.Transaction, error) {
	if c.socket == nil {
		return nil, errors.New("blockbook client not connected")
	}
	resp, err := c.socket.Ack("message", socketioReq{"getAddressTxids", []interface{}{
		[]string{addr.String()},
		map[string]interface{}{
			"start":        1000000000,
			"end":          fromHeight,
			"queryMempool": false,
		},
	}}, RequestTimeout)
	if err != nil {
		return nil, err
	}

	type (
		txids struct {
			Result []string `json:"result"`
		}

		txOrError struct {
			tx  iwallet.Transaction
			err error
		}
	)

	var ids txids
	if err := json.Unmarshal([]byte(resp), &ids); err != nil {
		return nil, err
	}

	var (
		wg  sync.WaitGroup
		txs = make([]iwallet.Transaction, 0, len(ids.Result))
		ch  = make(chan txOrError, len(ids.Result))
	)
	wg.Add(len(ids.Result))

	for _, id := range ids.Result {
		go func() {
			tx, err := c.GetTransaction(iwallet.TransactionID(id))
			ch <- txOrError{tx, err}
			wg.Done()
		}()
	}

	wg.Wait()
	close(ch)

	for result := range ch {
		if result.err != nil {
			return nil, result.err
		}

		txs = append(txs, result.tx)
	}

	return txs, nil
}

func (c *BlockbookClient) GetTransaction(id iwallet.TransactionID) (iwallet.Transaction, error) {
	resp, err := c.client.Get(c.clientUrl + "/tx/" + id.String())
	if err != nil {
		return iwallet.Transaction{}, err
	}

	if resp.StatusCode != http.StatusOK {
		return iwallet.Transaction{}, errors.New("not found")
	}

	decoder := json.NewDecoder(resp.Body)

	var tx transaction
	if err := decoder.Decode(&tx); err != nil {
		return iwallet.Transaction{}, err
	}

	return buildTransaction(&tx, c.coinType)
}

func (c *BlockbookClient) IsBlockInMainChain(block iwallet.BlockInfo) (bool, error) {
	type BlockHash struct {
		Hash string `json:"blockHash"`
	}

	resp, err := c.client.Get(c.clientUrl + "/block-index/" + strconv.Itoa(int(block.Height)))
	if err != nil {
		return false, err
	}

	if resp.StatusCode != http.StatusOK {
		return false, errors.New("incorrect status code")
	}

	decoder := json.NewDecoder(resp.Body)

	var hash BlockHash
	if err := decoder.Decode(&hash); err != nil {
		return false, err
	}

	return block.BlockID.String() == hash.Hash, nil
}

func (c *BlockbookClient) SubscribeTransactions(addrs []iwallet.Address) (*base.TransactionSubscription, error) {
	if c.socket == nil {
		return nil, errors.New("blockbook client not connected")
	}

	c.subMtx.Lock()
	defer c.subMtx.Unlock()

	sub := &base.TransactionSubscription{
		Out:         make(chan iwallet.Transaction),
		Subscribe:   make(chan []iwallet.Address),
		Unsubscribe: make(chan []iwallet.Address),
	}

	addrStrs := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		addrStrs = append(addrStrs, addr.String())
	}

	args := []interface{}{
		"bitcoind/addresstxid",
		addrStrs,
	}
	if err := c.socket.Emit("subscribe", args); err != nil {
		return nil, err
	}

	id := rand.Int31()
	c.txSubs[id] = sub

	subClose := make(chan struct{})

	sub.Close = func() {
		close(sub.Out)
		close(subClose)
		c.subMtx.Lock()
		delete(c.txSubs, id)
		c.subMtx.Unlock()
	}

	go func() {
		for {
			select {
			case <-subClose:
				return
			case <-c.shutdown:
				return
			case addrs := <-sub.Subscribe:
				addrStrs := make([]string, 0, len(addrs))
				for _, addr := range addrs {
					addrStrs = append(addrStrs, addr.String())
				}
				args := []interface{}{
					"bitcoind/addresstxid",
					addrStrs,
				}
				c.socket.Emit("subscribe", args)
			}
		}
	}()

	return sub, nil
}

func (c *BlockbookClient) SubscribeBlocks() (*base.BlockSubscription, error) {
	if c.socket == nil {
		return nil, errors.New("blockbook client not connected")
	}

	c.subMtx.Lock()
	defer c.subMtx.Unlock()

	sub := &base.BlockSubscription{
		Out: make(chan iwallet.BlockInfo),
	}

	id := rand.Int31()
	c.blockSubs[id] = sub

	sub.Close = func() {
		c.subMtx.Lock()
		delete(c.blockSubs, id)
		c.subMtx.Unlock()
		close(sub.Out)
	}

	if err := c.socket.Emit("subscribe", protocol.ToArgArray("bitcoind/hashblock")); err != nil {
		return nil, err
	}

	return sub, nil
}

func (c *BlockbookClient) Broadcast(serializedTx []byte) error {
	resp, err := c.client.Post(c.clientUrl+"/sendtx", "text/plain", bytes.NewReader([]byte(hex.EncodeToString(serializedTx))))
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		body, err := ioutil.ReadAll(resp.Body)
		if err == nil {
			return errors.New(string(body))
		}
		return fmt.Errorf("transaction broadcast failed. status %d", resp.StatusCode)
	}
	return nil
}

func (c *BlockbookClient) Close() error {
	c.subMtx.Lock()
	defer c.subMtx.Unlock()

	close(c.shutdown)
	if c.socket != nil {
		c.socket.Close()
	}
	return nil
}

func (c *BlockbookClient) connectSocket() {
	bo := backoff.NewExponentialBackOff()
	socketUrl := strings.Replace(strings.TrimSuffix(c.clientUrl, "/api"), "https://", "wss://", 1)

	s, err := gosocketio.Dial(socketUrl+"/socket.io/", GetDefaultWebsocketTransport(nil))
	if err == nil {
		err = c.listenEvents(s)
		if err == nil {
			c.socket = s
			return
		}
		s.Close()
	}

	go func() {
		for {
			s, err := gosocketio.Dial(socketUrl+"/socket.io/", GetDefaultWebsocketTransport(nil))
			if err != nil {
				select {
				case <-time.After(bo.NextBackOff()):
					continue
				case <-c.shutdown:
					return
				}
			}
			err = c.listenEvents(s)
			if err != nil {
				s.Close()
				select {
				case <-time.After(bo.NextBackOff()):
					continue
				case <-c.shutdown:
					return
				}
			}
			c.socket = s
			break
		}
	}()
}

func (c *BlockbookClient) listenEvents(socket *gosocketio.Client) error {
	err := socket.On("bitcoind/addresstxid", func(h *gosocketio.Channel, arg interface{}) {
		m, ok := arg.(map[string]interface{})
		if !ok {
			return
		}
		for _, v := range m {
			txid, ok := v.(string)
			if !ok {
				return
			}
			tx, err := c.GetTransaction(iwallet.TransactionID(txid))
			if err == nil {
				c.subMtx.Lock()
				for _, sub := range c.txSubs {
					sub.Out <- tx
				}
				c.subMtx.Unlock()
			}
		}
	})
	if err != nil {
		return err
	}
	return socket.On("bitcoind/hashblock", func(h *gosocketio.Channel, arg interface{}) {
		info, err := c.GetBlockchainInfo()
		if err != nil {
			return
		}
		c.subMtx.Lock()
		for _, sub := range c.blockSubs {
			sub.Out <- info
		}
		c.subMtx.Unlock()
	})
}

type transaction struct {
	Txid    string `json:"txid"`
	Version int    `json:"version"`
	Vin     []struct {
		PrevHash  string   `json:"txid"`
		Vout      int      `json:"vout"`
		Addresses []string `json:"addresses"`
		Value     string   `json:"value"`
	} `json:"vin"`
	Vout []struct {
		Value        string `json:"value"`
		ScriptPubkey struct {
			Addresses []string `json:"addresses"`
		} `json:"scriptPubKey"`
	} `json:"vout"`
	BlockHash   string `json:"blockhash"`
	BlockHeight int    `json:"blockheight"`
	Time        int64  `json:"time"`
	BlockTime   int64  `json:"blocktime"`
}

func buildTransaction(transaction *transaction, ct iwallet.CoinType) (iwallet.Transaction, error) {
	var blockInfo *iwallet.BlockInfo
	if transaction.BlockHash != "" {
		blockInfo = &iwallet.BlockInfo{
			Height:    uint64(transaction.BlockHeight),
			BlockID:   iwallet.BlockID(transaction.BlockHash),
			BlockTime: time.Unix(transaction.BlockTime, 0),
		}
	}

	tx := iwallet.Transaction{
		Height:    uint64(transaction.BlockHeight),
		BlockInfo: blockInfo,
		ID:        iwallet.TransactionID(transaction.Txid),
		Timestamp: time.Unix(transaction.Time, 0),
	}

	for _, in := range transaction.Vin {
		prevHash, err := hex.DecodeString(in.PrevHash)
		if err != nil {
			return tx, err
		}

		index := make([]byte, 4)
		binary.LittleEndian.PutUint32(index, uint32(in.Vout))

		f, err := strconv.ParseFloat(in.Value, 64)
		if err != nil {
			return tx, err
		}

		amt, err := btcutil.NewAmount(f)
		if err != nil {
			return tx, err
		}

		from := iwallet.SpendInfo{
			Amount: iwallet.NewAmount(uint64(amt.ToUnit(btcutil.AmountSatoshi))),
			ID:     append(prevHash, index...),
		}
		if len(in.Addresses) > 0 {
			from.Address = iwallet.NewAddress(in.Addresses[0], ct)
		}

		tx.From = append(tx.From, from)
	}

	txidBytes, err := hex.DecodeString(transaction.Txid)
	if err != nil {
		return tx, err
	}

	for i, out := range transaction.Vout {
		index := make([]byte, 4)
		binary.LittleEndian.PutUint32(index, uint32(i))

		f, err := strconv.ParseFloat(out.Value, 64)
		if err != nil {
			return tx, err
		}

		amt, err := btcutil.NewAmount(f)
		if err != nil {
			return tx, err
		}

		to := iwallet.SpendInfo{
			Amount: iwallet.NewAmount(uint64(amt.ToUnit(btcutil.AmountSatoshi))),
			ID:     append(txidBytes, index...),
		}

		if len(out.ScriptPubkey.Addresses) != 0 {
			to.Address = iwallet.NewAddress(out.ScriptPubkey.Addresses[0], ct)
		}

		tx.To = append(tx.To, to)
	}
	return tx, nil
}
