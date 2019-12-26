package base

import (
	"github.com/cpacia/multiwallet/database"
	"github.com/cpacia/multiwallet/database/sqlitedb"
	iwallet "github.com/cpacia/wallet-interface"
	"github.com/op/go-logging"
	"testing"
	"time"
)

func TestRebroadcaster(t *testing.T) {
	db, err := sqlitedb.NewMemoryDB()
	if err != nil {
		t.Fatal(err)
	}
	if err := database.InitializeDatabase(db); err != nil {
		t.Fatal(err)
	}
	logger, err := logging.GetLogger("test")
	if err != nil {
		t.Fatal(err)
	}

	client := NewMockChainClient()
	sub, err := client.SubscribeBlocks()
	if err != nil {
		t.Fatal(err)
	}

	rebroadcaster := NewRebroadcaster(db, logger, iwallet.CtMock, client.Broadcast, sub)

	go rebroadcaster.Start()

	<-time.After(time.Second)

	err = db.Update(func(tx database.Tx) error {
		return tx.Save(&database.UnconfirmedTransaction{
			Txid:    "abc",
			TxBytes: []byte{0xff},
			Coin:    iwallet.CtMock,
		})
	})
	if err != nil {
		t.Fatal(err)
	}

	client.GenerateBlock()

	<-time.After(time.Second)

	var unconf []database.UnconfirmedTransaction
	err = db.Update(func(tx database.Tx) error {
		return tx.Read().Find(&unconf).Error
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(unconf) != 0 {
		t.Errorf("Expected 0 txs got %d", len(unconf))
	}
}
