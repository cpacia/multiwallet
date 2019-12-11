package bchd

import (
	"bytes"
	"context"
	"errors"
	"github.com/cenkalti/backoff"
	"github.com/cpacia/multiwallet/base"
	iwallet "github.com/cpacia/wallet-interface"
	"github.com/gcash/bchd/bchrpc/pb"
	"github.com/gcash/bchd/chaincfg/chainhash"
	"github.com/gcash/bchd/wire"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	"math/rand"
	"sync"
	"time"
)

// BchdClient is a Bitcoin Cash only client that uses the BCHD gRPC interface.
// While BlockBook also works for Bitcoin Cash, BCHD tends to be faster, more
// reliable, and has a better interface.
type BchdClient struct {
	client    pb.BchrpcClient
	clientUrl string
	conn      *grpc.ClientConn
	subMtx    sync.Mutex
	txSubs    map[int32]*base.TransactionSubscription
	blockSubs map[int32]*base.BlockSubscription
}

// NewBchdClient returns a new BchdClient connected to the provided URL.
// Note this assumes the server is using a valid SSL certificate.
func NewBchdClient(url string) (*BchdClient, error) {
	client := &BchdClient{
		clientUrl: url,
		subMtx:    sync.Mutex{},
		txSubs:    make(map[int32]*base.TransactionSubscription),
		blockSubs: make(map[int32]*base.BlockSubscription),
	}
	client.connect()

	return client, nil
}

func (c *BchdClient) GetBlockchainInfo() (iwallet.BlockInfo, error) {
	if c.client == nil {
		return iwallet.BlockInfo{}, errors.New("client not connected")
	}
	bcInfo, err := c.client.GetBlockchainInfo(context.Background(), &pb.GetBlockchainInfoRequest{})
	if err != nil {
		return iwallet.BlockInfo{}, err
	}

	bestBlockInfo, err := c.client.GetBlockInfo(context.Background(), &pb.GetBlockInfoRequest{
		HashOrHeight: &pb.GetBlockInfoRequest_Hash{
			Hash: bcInfo.BestBlockHash,
		},
	})
	if err != nil {
		return iwallet.BlockInfo{}, err
	}

	bestHash, err := chainhash.NewHash(bcInfo.BestBlockHash)
	if err != nil {
		return iwallet.BlockInfo{}, err
	}

	prevHash, err := chainhash.NewHash(bestBlockInfo.Info.PreviousBlock)
	if err != nil {
		return iwallet.BlockInfo{}, err
	}

	return iwallet.BlockInfo{
		Height:    uint64(bcInfo.BestHeight),
		BlockID:   iwallet.BlockID(bestHash.String()),
		BlockTime: time.Unix(bestBlockInfo.Info.Timestamp, 0),
		PrevBlock: iwallet.BlockID(prevHash.String()),
	}, nil
}

func (c *BchdClient) GetAddressTransactions(addr iwallet.Address, fromHeight uint64) ([]iwallet.Transaction, error) {
	if c.client == nil {
		return nil, errors.New("client not connected")
	}
	resp, err := c.client.GetAddressTransactions(context.Background(), &pb.GetAddressTransactionsRequest{
		Address: addr.String(),
		StartBlock: &pb.GetAddressTransactionsRequest_Height{
			Height: int32(fromHeight),
		},
	})
	if err != nil {
		return nil, err
	}

	txs := make([]iwallet.Transaction, 0, len(resp.ConfirmedTransactions)+len(resp.UnconfirmedTransactions))
	for _, conf := range resp.ConfirmedTransactions {
		tx, err := buildTransaction(conf)
		if err != nil {
			return nil, err
		}

		txs = append(txs, tx)
	}
	for _, unconf := range resp.UnconfirmedTransactions {
		tx, err := buildTransaction(unconf.Transaction)
		if err != nil {
			return nil, err
		}

		txs = append(txs, tx)
	}
	return txs, nil
}

func (c *BchdClient) GetTransaction(id iwallet.TransactionID) (iwallet.Transaction, error) {
	if c.client == nil {
		return iwallet.Transaction{}, errors.New("client not connected")
	}
	ch, err := chainhash.NewHashFromStr(id.String())
	if err != nil {
		return iwallet.Transaction{}, err
	}

	resp, err := c.client.GetTransaction(context.Background(), &pb.GetTransactionRequest{
		Hash: ch.CloneBytes(),
	})
	if err != nil {
		return iwallet.Transaction{}, err
	}

	return buildTransaction(resp.Transaction)
}

func (c *BchdClient) IsBlockInMainChain(block iwallet.BlockInfo) (bool, error) {
	if c.client == nil {
		return false, errors.New("client not connected")
	}
	blockHash, err := chainhash.NewHashFromStr(block.BlockID.String())
	if err != nil {
		return false, err
	}

	blockInfo, err := c.client.GetBlockInfo(context.Background(), &pb.GetBlockInfoRequest{
		HashOrHeight: &pb.GetBlockInfoRequest_Hash{
			Hash: blockHash.CloneBytes(),
		},
	})
	if status.Code(err) == codes.NotFound {
		return false, nil
	} else if err != nil {
		return false, err
	}
	return blockInfo.Info.Confirmations > 0, nil
}

func (c *BchdClient) SubscribeTransactions(addrs []iwallet.Address) (*base.TransactionSubscription, error) {
	if c.client == nil {
		return nil, errors.New("client not connected")
	}
	c.subMtx.Lock()
	defer c.subMtx.Unlock()

	sub := &base.TransactionSubscription{
		Out:         make(chan iwallet.Transaction),
		Subscribe:   make(chan iwallet.Address),
		Unsubscribe: make(chan iwallet.Address),
	}

	addrStrs := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		addrStrs = append(addrStrs, addr.String())
	}
	stream, err := c.client.SubscribeTransactionStream(context.Background())
	if err != nil {
		return nil, err
	}

	err = stream.Send(&pb.SubscribeTransactionsRequest{
		Subscribe: &pb.TransactionFilter{
			Addresses: addrStrs,
		},
		IncludeMempool: true,
		IncludeInBlock: true,
	})
	if err != nil {
		return nil, err
	}

	id := rand.Int31()
	c.txSubs[id] = sub

	subClose := make(chan struct{})

	sub.Close = func() {
		stream.CloseSend()
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
			case addr := <-sub.Subscribe:
				stream.Send(&pb.SubscribeTransactionsRequest{
					Subscribe: &pb.TransactionFilter{
						Addresses: []string{addr.String()},
					},
					IncludeMempool: true,
					IncludeInBlock: true,
				})
			case addr := <-sub.Unsubscribe:
				stream.Send(&pb.SubscribeTransactionsRequest{
					Unsubscribe: &pb.TransactionFilter{
						Addresses: []string{addr.String()},
					},
				})
			}
		}
	}()

	go func() {
		for {
			txNtf, err := stream.Recv()
			if err != nil {
				return
			}
			if txNtf.Type == pb.TransactionNotification_CONFIRMED {
				tx, err := buildTransaction(txNtf.GetConfirmedTransaction())
				if err != nil {
					continue
				}
				sub.Out <- tx
			} else if txNtf.Type == pb.TransactionNotification_UNCONFIRMED {
				tx, err := buildTransaction(txNtf.GetUnconfirmedTransaction().Transaction)
				if err != nil {
					continue
				}
				sub.Out <- tx
			}
		}
	}()
	return sub, nil
}

func (c *BchdClient) SubscribeBlocks() (*base.BlockSubscription, error) {
	if c.client == nil {
		return nil, errors.New("client not connected")
	}
	c.subMtx.Lock()
	defer c.subMtx.Unlock()

	sub := &base.BlockSubscription{
		Out: make(chan iwallet.BlockInfo),
	}

	stream, err := c.client.SubscribeBlocks(context.Background(), &pb.SubscribeBlocksRequest{})
	if err != nil {
		return nil, err
	}

	id := rand.Int31()
	c.blockSubs[id] = sub

	sub.Close = func() {
		stream.CloseSend()
		c.subMtx.Lock()
		delete(c.blockSubs, id)
		c.subMtx.Unlock()
		close(sub.Out)
	}
	go func() {
		for {
			blockNotf, err := stream.Recv()
			if err != nil {
				return
			}
			if blockNotf.Type != pb.BlockNotification_CONNECTED {
				continue
			}
			info := blockNotf.GetBlockInfo()

			blockHash, err := chainhash.NewHash(info.Hash)
			if err != nil {
				continue
			}
			prevHash, err := chainhash.NewHash(info.PreviousBlock)
			if err != nil {
				continue
			}

			sub.Out <- iwallet.BlockInfo{
				BlockID:   iwallet.BlockID(blockHash.String()),
				PrevBlock: iwallet.BlockID(prevHash.String()),
				BlockTime: time.Unix(info.Timestamp, 0),
				Height:    uint64(info.Height),
			}
		}
	}()
	return sub, nil
}

func (c *BchdClient) Broadcast(serializedTx []byte) error {
	if c.client == nil {
		return errors.New("client not connected")
	}
	_, err := c.client.SubmitTransaction(context.Background(), &pb.SubmitTransactionRequest{
		Transaction: serializedTx,
	})
	return err
}

func (c *BchdClient) Close() error {
	c.subMtx.Lock()
	defer c.subMtx.Unlock()

	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

func (c *BchdClient) connect() {
	tlsOption := grpc.WithTransportCredentials(credentials.NewClientTLSFromCert(nil, ""))
	opts := []grpc.DialOption{tlsOption}

	conn, err := grpc.Dial(c.clientUrl, opts...)
	if err == nil {
		c.conn = conn
		c.client = pb.NewBchrpcClient(conn)
		return
	}

	go func() {
		bo := backoff.NewExponentialBackOff()
		for {
			conn, err := grpc.Dial(c.clientUrl, opts...)
			if err != nil {
				time.Sleep(bo.NextBackOff())
				continue
			}
			c.conn = conn
			c.client = pb.NewBchrpcClient(conn)
			break
		}
	}()
}

func buildTransaction(transaction *pb.Transaction) (iwallet.Transaction, error) {
	var blockInfo *iwallet.BlockInfo
	if transaction.BlockHash != nil {
		blockHash, err := chainhash.NewHash(transaction.BlockHash)
		if err != nil {
			return iwallet.Transaction{}, err
		}

		blockInfo = &iwallet.BlockInfo{
			Height:    uint64(transaction.BlockHeight),
			BlockID:   iwallet.BlockID(blockHash.String()),
			BlockTime: time.Unix(transaction.Timestamp, 0),
		}
	}

	txHash, err := chainhash.NewHash(transaction.Hash)
	if err != nil {
		return iwallet.Transaction{}, err
	}

	tx := iwallet.Transaction{
		Height:    uint64(transaction.BlockHeight),
		BlockInfo: blockInfo,
		ID:        iwallet.TransactionID(txHash.String()),
		Timestamp: time.Unix(transaction.Timestamp, 0),
	}

	for _, in := range transaction.Inputs {
		prevHash, err := chainhash.NewHash(in.Outpoint.Hash)
		if err != nil {
			return tx, err
		}

		outpoint := wire.NewOutPoint(prevHash, in.Outpoint.Index)

		var buf bytes.Buffer
		if err := outpoint.Serialize(&buf); err != nil {
			return tx, err
		}

		from := iwallet.SpendInfo{
			Address: iwallet.NewAddress(in.Address, iwallet.CtBitcoinCash),
			Amount:  iwallet.NewAmount(in.Value),
			ID:      buf.Bytes(),
		}

		tx.From = append(tx.From, from)
	}

	for i, out := range transaction.Outputs {
		outpoint := wire.NewOutPoint(txHash, uint32(i))

		var buf bytes.Buffer
		if err := outpoint.Serialize(&buf); err != nil {
			return tx, err
		}

		to := iwallet.SpendInfo{
			Address: iwallet.NewAddress(out.Address, iwallet.CtBitcoinCash),
			Amount:  iwallet.NewAmount(out.Value),
			ID:      buf.Bytes(),
		}

		tx.To = append(tx.To, to)
	}
	return tx, nil
}
