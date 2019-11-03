package base

import iwallet "github.com/cpacia/wallet-interface"

type BlockSubscription struct {
	Out   chan iwallet.BlockInfo
	Close func()
}

type TransactionSubscription struct {
	Out   chan iwallet.Transaction
	Close func()
}

type ChainClient interface {
	GetBlockchainInfo() (iwallet.BlockInfo, error)

	GetAddressTransactions(addr iwallet.Address, fromHeight uint64) ([]iwallet.Transaction, error)

	GetTransactionConfirmationInfo(id iwallet.TransactionID) (iwallet.BlockInfo, error)

	GetBlockConfirmations(id iwallet.BlockID) (uint64, error)

	SubscribeTransactions(addrs []iwallet.Address) (*TransactionSubscription, error)

	SubscribeBlocks() (*BlockSubscription, error)
}
