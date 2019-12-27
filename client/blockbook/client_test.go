package blockbook

import (
	"encoding/hex"
	gosocketio "github.com/OpenBazaar/golang-socketio"
	iwallet "github.com/cpacia/wallet-interface"
	"github.com/jarcoal/httpmock"
	"net/http"
	"testing"
	"time"
)

func TestBlockbookClient_GetBlockchainInfo(t *testing.T) {
	client, err := NewBlockbookClient("https://example.com/api", iwallet.CtMock)
	if err != nil {
		t.Fatal(err)
	}

	httpmock.RegisterResponder("GET", client.clientUrl,
		httpmock.NewStringResponder(200, `{"blockbook": {"lastBlockTime": "2019-12-27T03:48:06.17252601Z"}, "backend": {"blocks": 100000, "bestblockhash": "000000000000000000059db7d02e5a408dea5a55a44276fa89551749103590fa"}}`))

	httpmock.RegisterResponder("GET", client.clientUrl+"/block-index/99999",
		httpmock.NewStringResponder(200, `{"blockHash": "00000000000000000003657bf1583f9f9ef196cb80bb3c72aeecbb22f3c581c4"}`))

	httpmock.Activate()
	defer httpmock.Deactivate()

	info, err := client.GetBlockchainInfo()
	if err != nil {
		t.Fatal(err)
	}

	if info.Height != 100000 {
		t.Errorf("Expected height 100000, got %d", info.Height)
	}
	expectedBlockID := "000000000000000000059db7d02e5a408dea5a55a44276fa89551749103590fa"
	if info.BlockID.String() != expectedBlockID {
		t.Errorf("Expected block ID %s, got %s", expectedBlockID, info.BlockID)
	}
	expectedPrevID := "00000000000000000003657bf1583f9f9ef196cb80bb3c72aeecbb22f3c581c4"
	if info.PrevBlock.String() != expectedPrevID {
		t.Errorf("Expected prev ID %s, got %s", expectedPrevID, info.PrevBlock)
	}
	expectedTime := "2019-12-27 03:48:06.17252601 +0000 UTC"
	if info.BlockTime.String() != expectedTime {
		t.Errorf("Expected time %s, got %s", expectedTime, info.BlockTime.String())
	}
}

func TestBlockbookClient_GetTransaction(t *testing.T) {
	client, err := NewBlockbookClient("https://example.com/api", iwallet.CtBitcoin)
	if err != nil {
		t.Fatal(err)
	}

	httpmock.RegisterResponder("GET", client.clientUrl+"/tx/2a4cfac4cb8a322a31ac683bf6f2f05b6a5a1788af4e23a6a91a25fc7d891ce0",
		httpmock.NewStringResponder(200, `{"txid":"2a4cfac4cb8a322a31ac683bf6f2f05b6a5a1788af4e23a6a91a25fc7d891ce0","version":2,"locktime":609858,"vin":[{"txid":"88e9d70258ddcec90be40aa90990aadf6829f00cbd94643e084790ed6c57531a","vout":32,"sequence":4294967294,"n":0,"scriptSig":{"hex":"160014644c9d11c03ed7210afdaf1ee47c74d8869cd3a8"},"addresses":["3Fxe7hfikmEM4ATc2h5enZFLdKDpw8eZc7"],"value":"2.81414"}],"vout":[{"value":"0.872536","n":0,"scriptPubKey":{"hex":"a914c6c1ca62f2bf5180d36603cddfaa5ae4ed8c939c87","addresses":["3KowsLAQ2ZZ3FmwnBR8kiEzwnC2LqDNcmK"]},"spent":false},{"value":"1.9411","n":1,"scriptPubKey":{"hex":"76a91445c24214c06f7b2a2f69f883bf0c3c67250e901288ac","addresses":["17MrLXcJWnCbyJUXkvUeYeQEyQwYY5gMAU"]},"spent":false}],"blockhash":"00000000000000000003657bf1583f9f9ef196cb80bb3c72aeecbb22f3c581c4","blockheight":609951,"confirmations":4,"time":1577417904,"blocktime":1577417904,"valueOut":"2.813636","valueIn":"2.81414","fees":"0.000504","hex":"020000000001011a53576ced9047083e6494bd0cf02968dfaa9009a90ae40bc9cedd5802d7e9882000000017160014644c9d11c03ed7210afdaf1ee47c74d8869cd3a8feffffff02606233050000000017a914c6c1ca62f2bf5180d36603cddfaa5ae4ed8c939c8730e2910b000000001976a91445c24214c06f7b2a2f69f883bf0c3c67250e901288ac0247304402206779906ee2c3ec0776aa992c19a3d22c0c5b421908cf1c4f1f1a37d5c96643500220322414d13e08cd97c87f30820cba7e392cce27b700da9e071f7fa94ba3bdaa070121033eeb6faf4ef2207f025e19da3707eb73b514f2941ba9ca5b29d6f54617737b94424e0900"}`))

	httpmock.Activate()
	defer httpmock.Deactivate()

	tx, err := client.GetTransaction(iwallet.TransactionID("2a4cfac4cb8a322a31ac683bf6f2f05b6a5a1788af4e23a6a91a25fc7d891ce0"))
	if err != nil {
		t.Fatal(err)
	}

	expectedTxid := "2a4cfac4cb8a322a31ac683bf6f2f05b6a5a1788af4e23a6a91a25fc7d891ce0"
	if tx.ID.String() != expectedTxid {
		t.Errorf("Expected txid %s, got %s", expectedTxid, tx.ID)
	}

	if len(tx.From) != 1 {
		t.Errorf("Expected 1 input got %d", len(tx.From))
	}

	expectedFromAddr := "3Fxe7hfikmEM4ATc2h5enZFLdKDpw8eZc7"
	if tx.From[0].Address.String() != expectedFromAddr {
		t.Errorf("Expected from address %s, got %s", expectedFromAddr, tx.From[0].Address.String())
	}

	expectedFromAmount := "281414000"
	if tx.From[0].Amount.String() != expectedFromAmount {
		t.Errorf("Expected from amount %s, got %s", expectedFromAmount, tx.From[0].Amount.String())
	}

	expectedFromID := "88e9d70258ddcec90be40aa90990aadf6829f00cbd94643e084790ed6c57531a20000000"
	if hex.EncodeToString(tx.From[0].ID) != expectedFromID {
		t.Errorf("Expected from ID %s, got %s", expectedFromID, hex.EncodeToString(tx.From[0].ID))
	}

	if len(tx.To) != 2 {
		t.Errorf("Expected 2 ouotputs got %d", len(tx.To))
	}

	expectedToAddr0 := "3KowsLAQ2ZZ3FmwnBR8kiEzwnC2LqDNcmK"
	if tx.To[0].Address.String() != expectedToAddr0 {
		t.Errorf("Expected to address %s, got %s", expectedToAddr0, tx.To[0].Address.String())
	}

	expectedToAmount0 := "87253600"
	if tx.To[0].Amount.String() != expectedToAmount0 {
		t.Errorf("Expected to amount %s, got %s", expectedToAmount0, tx.To[0].Amount.String())
	}

	expectedToID0 := "2a4cfac4cb8a322a31ac683bf6f2f05b6a5a1788af4e23a6a91a25fc7d891ce000000000"
	if hex.EncodeToString(tx.To[0].ID) != expectedToID0 {
		t.Errorf("Expected to ID %s, got %s", expectedToID0, hex.EncodeToString(tx.To[0].ID))
	}

	expectedToAddr1 := "17MrLXcJWnCbyJUXkvUeYeQEyQwYY5gMAU"
	if tx.To[1].Address.String() != expectedToAddr1 {
		t.Errorf("Expected to address %s, got %s", expectedToAddr1, tx.To[1].Address.String())
	}

	expectedToAmount1 := "194110000"
	if tx.To[1].Amount.String() != expectedToAmount1 {
		t.Errorf("Expected to amount %s, got %s", expectedToAmount1, tx.To[1].Amount.String())
	}

	expectedToID1 := "2a4cfac4cb8a322a31ac683bf6f2f05b6a5a1788af4e23a6a91a25fc7d891ce001000000"
	if hex.EncodeToString(tx.To[1].ID) != expectedToID1 {
		t.Errorf("Expected to ID %s, got %s", expectedToID1, hex.EncodeToString(tx.To[1].ID))
	}
}

func TestBlockbookClient_GetAddressTransactions(t *testing.T) {
	server := gosocketio.NewServer(GetDefaultWebsocketTransport())
	serveMux := http.NewServeMux()

	server.On("message", func(c *gosocketio.Channel, req *socketioReq) resultAddressTxids {
		return resultAddressTxids{[]string{"2a4cfac4cb8a322a31ac683bf6f2f05b6a5a1788af4e23a6a91a25fc7d891ce0"}}
	})

	serveMux.Handle("/socket.io/", server)
	go http.ListenAndServe("127.00.1:8080", serveMux)

	client, err := NewBlockbookClient("http://localhost:8080", iwallet.CtMock)
	if err != nil {
		t.Fatal(err)
	}

	httpmock.RegisterResponder("GET", client.clientUrl+"/tx/2a4cfac4cb8a322a31ac683bf6f2f05b6a5a1788af4e23a6a91a25fc7d891ce0",
		httpmock.NewStringResponder(200, `{"txid":"2a4cfac4cb8a322a31ac683bf6f2f05b6a5a1788af4e23a6a91a25fc7d891ce0","version":2,"locktime":609858,"vin":[{"txid":"88e9d70258ddcec90be40aa90990aadf6829f00cbd94643e084790ed6c57531a","vout":32,"sequence":4294967294,"n":0,"scriptSig":{"hex":"160014644c9d11c03ed7210afdaf1ee47c74d8869cd3a8"},"addresses":["3Fxe7hfikmEM4ATc2h5enZFLdKDpw8eZc7"],"value":"2.81414"}],"vout":[{"value":"0.872536","n":0,"scriptPubKey":{"hex":"a914c6c1ca62f2bf5180d36603cddfaa5ae4ed8c939c87","addresses":["3KowsLAQ2ZZ3FmwnBR8kiEzwnC2LqDNcmK"]},"spent":false},{"value":"1.9411","n":1,"scriptPubKey":{"hex":"76a91445c24214c06f7b2a2f69f883bf0c3c67250e901288ac","addresses":["17MrLXcJWnCbyJUXkvUeYeQEyQwYY5gMAU"]},"spent":false}],"blockhash":"00000000000000000003657bf1583f9f9ef196cb80bb3c72aeecbb22f3c581c4","blockheight":609951,"confirmations":4,"time":1577417904,"blocktime":1577417904,"valueOut":"2.813636","valueIn":"2.81414","fees":"0.000504","hex":"020000000001011a53576ced9047083e6494bd0cf02968dfaa9009a90ae40bc9cedd5802d7e9882000000017160014644c9d11c03ed7210afdaf1ee47c74d8869cd3a8feffffff02606233050000000017a914c6c1ca62f2bf5180d36603cddfaa5ae4ed8c939c8730e2910b000000001976a91445c24214c06f7b2a2f69f883bf0c3c67250e901288ac0247304402206779906ee2c3ec0776aa992c19a3d22c0c5b421908cf1c4f1f1a37d5c96643500220322414d13e08cd97c87f30820cba7e392cce27b700da9e071f7fa94ba3bdaa070121033eeb6faf4ef2207f025e19da3707eb73b514f2941ba9ca5b29d6f54617737b94424e0900"}`))

	httpmock.Activate()
	defer httpmock.Deactivate()

	if err := client.Open(); err != nil {
		t.Fatal(err)
	}

	txs, err := client.GetAddressTransactions(iwallet.NewAddress("abc", iwallet.CtMock), 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(txs) != 1 {
		t.Errorf("Expected 1 tx, got %d", len(txs))
	}

	expectedTxid := "2a4cfac4cb8a322a31ac683bf6f2f05b6a5a1788af4e23a6a91a25fc7d891ce0"
	if txs[0].ID.String() != expectedTxid {
		t.Errorf("Expected txid %s, got %s", expectedTxid, txs[0].ID)
	}
}

func TestBlockbookClient_IsBlockInMainChain(t *testing.T) {
	client, err := NewBlockbookClient("https://example.com/api", iwallet.CtMock)
	if err != nil {
		t.Fatal(err)
	}

	httpmock.RegisterResponder("GET", client.clientUrl+"/block-index/99999",
		httpmock.NewStringResponder(200, `{"blockHash": "00000000000000000003657bf1583f9f9ef196cb80bb3c72aeecbb22f3c581c4"}`))

	httpmock.Activate()
	defer httpmock.Deactivate()

	inMain, err := client.IsBlockInMainChain(iwallet.BlockInfo{Height: 99999, BlockID: iwallet.BlockID("00000000000000000003657bf1583f9f9ef196cb80bb3c72aeecbb22f3c581c4")})
	if err != nil {
		t.Fatal(err)
	}

	if !inMain {
		t.Errorf("Expected true, got false")
	}

	httpmock.RegisterResponder("GET", client.clientUrl+"/block-index/99999",
		httpmock.NewStringResponder(200, `{"blockHash": "00000000000000000003657bf1583f9f9ef196cb80bb3c72aeecbb22f3c581c4"}`))

	inMain, err = client.IsBlockInMainChain(iwallet.BlockInfo{Height: 99999, BlockID: iwallet.BlockID("0000000000000000000fffffffffff9f9ef196cb80bb3c72aeecbb22f3c581c4")})
	if err != nil {
		t.Fatal(err)
	}

	if inMain {
		t.Errorf("Expected false, got true")
	}
}

func TestBlockbookClient_Broadcast(t *testing.T) {
	client, err := NewBlockbookClient("https://example.com/api", iwallet.CtMock)
	if err != nil {
		t.Fatal(err)
	}

	httpmock.Activate()
	defer httpmock.Deactivate()

	httpmock.RegisterResponder("POST", client.clientUrl+"/sendtx",
		httpmock.NewStringResponder(200, ``))

	if err := client.Broadcast([]byte{0x00, 0x01, 0x02}); err != nil {
		t.Fatal(err)
	}

	httpmock.RegisterResponder("POST", client.clientUrl+"/sendtx",
		httpmock.NewStringResponder(400, ``))

	if err := client.Broadcast([]byte{0x00, 0x01, 0x02}); err == nil {
		t.Error("Expected error got nil")
	}
}

func TestBlockbookClient_SubscribeTransactions(t *testing.T) {
	server := gosocketio.NewServer(GetDefaultWebsocketTransport())
	serveMux := http.NewServeMux()

	err := server.On("subscribe", func(c *gosocketio.Channel, i interface{}) interface{} {
		a := i.([]interface{})
		addrs := a[1].([]interface{})
		c.Join("bitcoind/addresstxid-" + addrs[0].(string))
		data := map[string]interface{}{"address": addrs[0].(string), "txid": "2a4cfac4cb8a322a31ac683bf6f2f05b6a5a1788af4e23a6a91a25fc7d891ce0"}
		server.BroadcastTo("bitcoind/addresstxid-"+addrs[0].(string), "bitcoind/addresstxid", data)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	serveMux.Handle("/socket.io/", server)
	go http.ListenAndServe("127.0.0.1:8082", serveMux)

	client, err := NewBlockbookClient("http://localhost:8082", iwallet.CtMock)
	if err != nil {
		t.Fatal(err)
	}

	httpmock.RegisterResponder("GET", client.clientUrl+"/tx/2a4cfac4cb8a322a31ac683bf6f2f05b6a5a1788af4e23a6a91a25fc7d891ce0",
		httpmock.NewStringResponder(200, `{"txid":"2a4cfac4cb8a322a31ac683bf6f2f05b6a5a1788af4e23a6a91a25fc7d891ce0","version":2,"locktime":609858,"vin":[{"txid":"88e9d70258ddcec90be40aa90990aadf6829f00cbd94643e084790ed6c57531a","vout":32,"sequence":4294967294,"n":0,"scriptSig":{"hex":"160014644c9d11c03ed7210afdaf1ee47c74d8869cd3a8"},"addresses":["3Fxe7hfikmEM4ATc2h5enZFLdKDpw8eZc7"],"value":"2.81414"}],"vout":[{"value":"0.872536","n":0,"scriptPubKey":{"hex":"a914c6c1ca62f2bf5180d36603cddfaa5ae4ed8c939c87","addresses":["3KowsLAQ2ZZ3FmwnBR8kiEzwnC2LqDNcmK"]},"spent":false},{"value":"1.9411","n":1,"scriptPubKey":{"hex":"76a91445c24214c06f7b2a2f69f883bf0c3c67250e901288ac","addresses":["17MrLXcJWnCbyJUXkvUeYeQEyQwYY5gMAU"]},"spent":false}],"blockhash":"00000000000000000003657bf1583f9f9ef196cb80bb3c72aeecbb22f3c581c4","blockheight":609951,"confirmations":4,"time":1577417904,"blocktime":1577417904,"valueOut":"2.813636","valueIn":"2.81414","fees":"0.000504","hex":"020000000001011a53576ced9047083e6494bd0cf02968dfaa9009a90ae40bc9cedd5802d7e9882000000017160014644c9d11c03ed7210afdaf1ee47c74d8869cd3a8feffffff02606233050000000017a914c6c1ca62f2bf5180d36603cddfaa5ae4ed8c939c8730e2910b000000001976a91445c24214c06f7b2a2f69f883bf0c3c67250e901288ac0247304402206779906ee2c3ec0776aa992c19a3d22c0c5b421908cf1c4f1f1a37d5c96643500220322414d13e08cd97c87f30820cba7e392cce27b700da9e071f7fa94ba3bdaa070121033eeb6faf4ef2207f025e19da3707eb73b514f2941ba9ca5b29d6f54617737b94424e0900"}`))

	httpmock.Activate()
	defer httpmock.Deactivate()

	if err := client.Open(); err != nil {
		t.Fatal(err)
	}

	sub, err := client.SubscribeTransactions([]iwallet.Address{iwallet.NewAddress("abc", iwallet.CtMock)})
	if err != nil {
		t.Fatal(err)
	}

	select {
	case tx := <-sub.Out:
		expectedTxid := "2a4cfac4cb8a322a31ac683bf6f2f05b6a5a1788af4e23a6a91a25fc7d891ce0"
		if tx.ID.String() != expectedTxid {
			t.Errorf("Expected txid %s, got %s", expectedTxid, tx.ID)
		}
	case <-time.After(time.Second * 10):
		t.Fatal("Timed out waiting on subscription")
	}
}

func TestBlockbookClient_SubscribeBlocks(t *testing.T) {
	server := gosocketio.NewServer(GetDefaultWebsocketTransport())
	serveMux := http.NewServeMux()

	err := server.On("subscribe", func(c *gosocketio.Channel, i interface{}) interface{} {
		c.Join("bitcoind/hashblock")
		server.BroadcastTo("bitcoind/hashblock", "bitcoind/hashblock", "000000000000000000059db7d02e5a408dea5a55a44276fa89551749103590fa")
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	serveMux.Handle("/socket.io/", server)
	go http.ListenAndServe("127.0.0.1:8081", serveMux)

	client, err := NewBlockbookClient("http://localhost:8081", iwallet.CtMock)
	if err != nil {
		t.Fatal(err)
	}
	httpmock.RegisterResponder("GET", client.clientUrl,
		httpmock.NewStringResponder(200, `{"blockbook": {"lastBlockTime": "2019-12-27T03:48:06.17252601Z"}, "backend": {"blocks": 100000, "bestblockhash": "000000000000000000059db7d02e5a408dea5a55a44276fa89551749103590fa"}}`))

	httpmock.RegisterResponder("GET", client.clientUrl+"/block-index/99999",
		httpmock.NewStringResponder(200, `{"blockHash": "00000000000000000003657bf1583f9f9ef196cb80bb3c72aeecbb22f3c581c4"}`))

	httpmock.Activate()
	defer httpmock.Deactivate()

	if err := client.Open(); err != nil {
		t.Fatal(err)
	}

	sub, err := client.SubscribeBlocks()
	if err != nil {
		t.Fatal(err)
	}

	select {
	case info := <-sub.Out:
		if info.Height != 100000 {
			t.Errorf("Expected height 100000, got %d", info.Height)
		}
		expectedBlockID := "000000000000000000059db7d02e5a408dea5a55a44276fa89551749103590fa"
		if info.BlockID.String() != expectedBlockID {
			t.Errorf("Expected block ID %s, got %s", expectedBlockID, info.BlockID)
		}
		expectedPrevID := "00000000000000000003657bf1583f9f9ef196cb80bb3c72aeecbb22f3c581c4"
		if info.PrevBlock.String() != expectedPrevID {
			t.Errorf("Expected prev ID %s, got %s", expectedPrevID, info.PrevBlock)
		}
		expectedTime := "2019-12-27 03:48:06.17252601 +0000 UTC"
		if info.BlockTime.String() != expectedTime {
			t.Errorf("Expected time %s, got %s", expectedTime, info.BlockTime.String())
		}
	case <-time.After(time.Second * 10):
		t.Fatal("Timed out waiting on subscription")
	}
}

func TestBlockbookClient_OpenClose(t *testing.T) {
	server := gosocketio.NewServer(GetDefaultWebsocketTransport())
	serveMux := http.NewServeMux()

	serveMux.Handle("/socket.io/", server)
	go http.ListenAndServe("127.0.0.1:8083", serveMux)

	client, err := NewBlockbookClient("http://localhost:8083", iwallet.CtMock)
	if err != nil {
		t.Fatal(err)
	}

	if err := client.Open(); err != nil {
		t.Fatal(err)
	}

	txSub, err := client.SubscribeTransactions([]iwallet.Address{iwallet.NewAddress("abc", iwallet.CtMock)})
	if err != nil {
		t.Fatal(err)
	}

	blockSub, err := client.SubscribeTransactions([]iwallet.Address{iwallet.NewAddress("abc", iwallet.CtMock)})
	if err != nil {
		t.Fatal(err)
	}

	if err := client.Close(); err != nil {
		t.Fatal(err)
	}

	txSub.Close()
	blockSub.Close()
}
