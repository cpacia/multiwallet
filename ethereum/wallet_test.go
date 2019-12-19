package ethereum

import (
	"encoding/json"
	"fmt"
	"github.com/btcsuite/btcutil/hdkeychain"
	"github.com/cpacia/multiwallet/base"
	"github.com/cpacia/multiwallet/database"
	"github.com/cpacia/multiwallet/database/sqlitedb"
	iwallet "github.com/cpacia/wallet-interface"
	"testing"
	"time"
)

func TestEthereumWallet_CloseWallet(t *testing.T) {
	db, err := sqlitedb.NewMemoryDB()
	if err != nil {
		t.Fatal(err)
	}
	if err := database.InitializeDatabase(db); err != nil {
		t.Fatal(err)
	}
	w, err := NewEthereumWallet(&base.WalletConfig{
		ClientUrl: "https://rinkeby.infura.io",
		DB:        db,
		Testnet:   true,
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

	tx, err := w.client.GetTransaction(iwallet.TransactionID("0x5a6f5c52df5790bd114704e58afb7ba071e90d9e4cd0b6accd5304a64137cfb5"))
	if err != nil {
		t.Fatal(err)
	}
	out, err := json.MarshalIndent(&tx, "", "    ")
	if err != nil {
		t.Fatal()
	}
	fmt.Println(string(out))
}
