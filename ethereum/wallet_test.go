package ethereum

import (
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
		ClientUrl: "https://mainnet.infura.io",
		DB: db,
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

	fmt.Println(w.GetTransaction(iwallet.TransactionID("0xf203281fe3ee87635044e19da60ab3bce8a7dae30af85e9922be5e26553f696b")))

}
