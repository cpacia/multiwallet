package base

import iwallet "github.com/cpacia/wallet-interface"

type BlockSubscription struct {
	Out   chan iwallet.BlockInfo
	Close func()
}

type TransactionSubscription struct {
	Out         chan iwallet.Transaction
	Subscribe   chan iwallet.Address
	Unsubscribe chan iwallet.Address
	Close       func()
}

type ChainClient interface {
	GetBlockchainInfo() (iwallet.BlockInfo, error)

	GetAddressTransactions(addr iwallet.Address, fromHeight uint64) ([]iwallet.Transaction, error)

	GetTransaction(id iwallet.TransactionID) (iwallet.Transaction, error)

	IsBlockInMainChain(id iwallet.BlockID) (bool, error)

	SubscribeTransactions(addrs []iwallet.Address) (*TransactionSubscription, error)

	SubscribeBlocks() (*BlockSubscription, error)

	Broadcast(serializedTx []byte) error

	Close() error
}
