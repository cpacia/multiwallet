package base

import (
	"errors"
	"github.com/cpacia/multiwallet/database"
	iwallet "github.com/cpacia/wallet-interface"
	"github.com/op/go-logging"
	"gorm.io/gorm"
)

// Rebroadcaster handles rebroadcasting unconfirmed transactions.
type Rebroadcaster struct {
	db            database.Database
	coinType      iwallet.CoinType
	logger        *logging.Logger
	sub           *BlockSubscription
	broadcastFunc func(serializedTx []byte) error
	shutdown      chan struct{}
}

// NewRebroadcaster returns a new Rebroadcaster.
func NewRebroadcaster(db database.Database, logger *logging.Logger, coinType iwallet.CoinType, broadcastFunc func(serializedTx []byte) error, sub *BlockSubscription) *Rebroadcaster {
	return &Rebroadcaster{db: db, sub: sub, coinType: coinType, logger: logger, broadcastFunc: broadcastFunc, shutdown: make(chan struct{})}
}

// Start will run the rebroadcaster. Ever new block it will try
// to rebroadcast unconfirmed txs.
func (r *Rebroadcaster) Start() {
	for {
		select {
		case <-r.sub.Out:
			r.rebroadcast()
		case <-r.shutdown:
			return
		}
	}
}

// Stop will shutdown the rebroadcaster.
func (r *Rebroadcaster) Stop() {
	close(r.shutdown)
}

func (r *Rebroadcaster) rebroadcast() {
	var unconf []database.UnconfirmedTransaction
	err := r.db.View(func(tx database.Tx) error {
		return tx.Read().Where("coin=?", r.coinType.CurrencyCode()).Find(&unconf).Error
	})
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		r.logger.Errorf("Error loading unconfirmed txs for rebroadcast: %s", err)
		return
	}

	for _, utx := range unconf {
		if err := r.broadcastFunc(utx.TxBytes); err != nil {
			r.logger.Errorf("Error rebroadcasting tx %s: %s", utx.Txid, err)
			continue
		}
		err := r.db.Update(func(tx database.Tx) error {
			return tx.Delete("txid", utx.Txid, &utx)
		})
		if err != nil {
			r.logger.Errorf("Error deleting unconfirmed tx: %s", err)
		}
	}
}
