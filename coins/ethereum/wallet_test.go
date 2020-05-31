package ethereum

import (
	"encoding/json"
	"fmt"
	"github.com/btcsuite/btcutil/hdkeychain"
	"github.com/cpacia/multiwallet/base"
	"github.com/cpacia/multiwallet/database"
	"github.com/cpacia/multiwallet/database/sqlitedb"
	iwallet "github.com/cpacia/wallet-interface"
	"github.com/op/go-logging"
	"testing"
	"time"
)

func TestEthereumWallet_CloseWallet(t *testing.T) {
	return
	db, err := sqlitedb.NewMemoryDB()
	if err != nil {
		t.Fatal(err)
	}
	if err := database.InitializeDatabase(db); err != nil {
		t.Fatal(err)
	}
	w, err := NewEthereumWallet(&base.WalletConfig{
		ClientUrl: "https://mainnet.infura.io/v3/91c82af0169c4115940c76d331410749",
		DB:        db,
		Testnet:   false,
		Logger:    logging.MustGetLogger("eth"),
	})
	if err != nil {
		t.Fatal(err)
	}

	key, err := hdkeychain.NewKeyFromString("tprv8ZgxMBicQKsPeghT19pungdFLMJM2hMs3EEn5WtgobD7wuQSFQu4VNaEJXH9HS3RhhLT4wgZ3hj31m3kafuxhL9vfGTRtBVLSog4zjxW3L1")
	if err != nil {
		t.Fatal(err)
	}

	if !w.WalletExists() {
		if err := w.CreateWallet(*key, nil, time.Now()); err != nil {
			t.Fatal(err)
		}
	}

	if err := w.OpenWallet(); err != nil {
		t.Fatal(err)
	}

	defer w.CloseWallet()

	time.Sleep(time.Second * 5)

	tx, err := w.client.GetTransaction(iwallet.TransactionID("0x0feaa08977c131c491a2bc57422c557f07994713c35804c0e54615ff5fdacf3a"))
	if err != nil {
		t.Fatal(err)
	}
	out, err := json.MarshalIndent(&tx, "", "    ")
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(string(out))

	sub, err := w.client.SubscribeTransactions([]iwallet.Address{iwallet.NewAddress("0x0Fc809Dd1475cd6056B6D36A832CB53bCb2E8786", iwallet.CtEthereum)})
	if err != nil {
		t.Fatal(err)
	}

	tx2 := <-sub.Out
	out, err = json.MarshalIndent(&tx2, "", "    ")
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(string(out))
}
