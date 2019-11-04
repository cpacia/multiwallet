package base

import (
	"encoding/hex"
	"errors"
	iwallet "github.com/cpacia/wallet-interface"
	"math/rand"
	"sync"
	"time"
)

type MockChainClient struct {
	mtx       sync.RWMutex
	blocks    []iwallet.BlockInfo
	addrIndex map[iwallet.Address][]iwallet.Transaction
	txIndex   map[iwallet.TransactionID]iwallet.Transaction
	txSubs    map[iwallet.Address]*TransactionSubscription
	blockSubs map[int32]*BlockSubscription

	returnErr error
}

func NewMockChainClient() *MockChainClient {
	return &MockChainClient{
		mtx: sync.RWMutex{},
		blocks: []iwallet.BlockInfo{
			{
				BlockID:   "0000000000000000000000000000000000000000000000000000000000000000",
				PrevBlock: "",
				Height:    0,
				BlockTime: time.Now(),
			},
		},
		addrIndex: make(map[iwallet.Address][]iwallet.Transaction),
		txIndex:   make(map[iwallet.TransactionID]iwallet.Transaction),
		txSubs:    make(map[iwallet.Address]*TransactionSubscription),
		blockSubs: make(map[int32]*BlockSubscription),
	}
}

func (m *MockChainClient) GenerateBlock() {
	m.mtx.Lock()
	defer m.mtx.Unlock()

	r := make([]byte, 32)
	rand.Read(r)

	newBlock := iwallet.BlockInfo{
		BlockID:   iwallet.BlockID(hex.EncodeToString(r)),
		PrevBlock: m.blocks[len(m.blocks)-1].BlockID,
		Height:    m.blocks[len(m.blocks)-1].Height + 1,
		BlockTime: time.Now(),
	}

	m.blocks = append(m.blocks, newBlock)

	for _, txs := range m.addrIndex {
		for i := range txs {
			if txs[i].Height == 0 {
				txs[i].Height = newBlock.Height
				txs[i].BlockInfo = &newBlock
			}
		}
	}

	for txid, tx := range m.txIndex {
		tx.Height = newBlock.Height
		tx.BlockInfo = &newBlock
		m.txIndex[txid] = tx
	}

	go func() {
		for _, sub := range m.blockSubs {
			sub.Out <- newBlock
		}
	}()
}

func (m *MockChainClient) SetErrorResponse(err error) {
	m.mtx.Lock()
	defer m.mtx.Unlock()

	m.returnErr = err
}

func (m *MockChainClient) GetBlockchainInfo() (iwallet.BlockInfo, error) {
	m.mtx.RLock()
	defer m.mtx.RUnlock()

	if m.returnErr != nil {
		return iwallet.BlockInfo{}, m.returnErr
	}

	return m.blocks[len(m.blocks)-1], nil
}

func (m *MockChainClient) GetAddressTransactions(addr iwallet.Address, fromHeight uint64) ([]iwallet.Transaction, error) {
	m.mtx.RLock()
	defer m.mtx.RUnlock()

	if m.returnErr != nil {
		return nil, m.returnErr
	}

	txs := m.addrIndex[addr]
	return txs, nil
}

func (m *MockChainClient) GetTransaction(id iwallet.TransactionID) (iwallet.Transaction, error) {
	m.mtx.RLock()
	defer m.mtx.RUnlock()

	if m.returnErr != nil {
		return iwallet.Transaction{}, m.returnErr
	}

	tx, ok := m.txIndex[id]
	if !ok {
		return tx, errors.New("tx not found")
	}
	return tx, nil
}

func (m *MockChainClient) IsBlockInMainChain(id iwallet.BlockID) (bool, error) {
	m.mtx.RLock()
	defer m.mtx.RUnlock()

	if m.returnErr != nil {
		return false, m.returnErr
	}

	for _, block := range m.blocks {
		if block.BlockID == id {
			return true, nil
		}
	}
	return false, nil
}

func (m *MockChainClient) SubscribeTransactions(addrs []iwallet.Address) (*TransactionSubscription, error) {
	m.mtx.Lock()
	defer m.mtx.Unlock()

	if m.returnErr != nil {
		return nil, m.returnErr
	}

	sub := &TransactionSubscription{
		Out: make(chan iwallet.Transaction),
		Close: func() {
			m.mtx.Lock()
			defer m.mtx.Unlock()

			for _, addr := range addrs {
				delete(m.txSubs, addr)
			}
		},
	}

	for _, addr := range addrs {
		m.txSubs[addr] = sub
	}

	return sub, nil
}

func (m *MockChainClient) SubscribeBlocks() (*BlockSubscription, error) {
	m.mtx.Lock()
	defer m.mtx.Unlock()

	if m.returnErr != nil {
		return nil, m.returnErr
	}

	n := rand.Int31()
	sub := &BlockSubscription{
		Out: make(chan iwallet.BlockInfo),
		Close: func() {
			delete(m.blockSubs, n)
		},
	}

	m.blockSubs[n] = sub
	return sub, nil
}

func (m *MockChainClient) Broadcast(tx iwallet.Transaction) error {
	m.mtx.Lock()
	defer m.mtx.Unlock()

	if m.returnErr != nil {
		return m.returnErr
	}

	m.txIndex[tx.ID] = tx

	subs := make([]*TransactionSubscription, 0, len(tx.From)+len(tx.To))

	duplicateSub := func(sub *TransactionSubscription) bool {
		for _, s := range subs {
			if s == sub {
				return true
			}
		}
		return false
	}

	for _, from := range tx.From {
		m.addrIndex[from.Address] = append(m.addrIndex[from.Address], tx)

		sub, ok := m.txSubs[from.Address]
		if ok {
			if !duplicateSub(sub) {
				subs = append(subs, sub)
			}
		}
	}

	for _, to := range tx.To {
		m.addrIndex[to.Address] = append(m.addrIndex[to.Address], tx)

		sub, ok := m.txSubs[to.Address]
		if ok {
			if !duplicateSub(sub) {
				subs = append(subs, sub)
			}
		}
	}

	go func() {
		for _, sub := range subs {
			sub.Out <- tx
		}
	}()

	return nil
}
