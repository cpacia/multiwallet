package base

import (
	"encoding/hex"
	"errors"
	expbackoff "github.com/cenkalti/backoff"
	"github.com/cpacia/multiwallet/database"
	iwallet "github.com/cpacia/wallet-interface"
	"github.com/jinzhu/gorm"
	"github.com/op/go-logging"
	"sync"
	"time"
)

// ChainConfig holds all the information need to instantiate a new ChainManager
type ChainConfig struct {
	Client          ChainClient
	DB              database.Database
	KeyManager      *KeyManager
	CoinType        iwallet.CoinType
	Logger          *logging.Logger
	TransactionChan chan<- iwallet.Transaction
}

// ChainManager manages the downloading of transactions for the wallet.
// It updates transaction confirmations and keeps track of utxos.
type ChainManager struct {
	client          ChainClient
	best            iwallet.BlockInfo
	coinType        iwallet.CoinType
	keyManager      *KeyManager
	db              database.Database
	logger          *logging.Logger
	backoff         *expbackoff.ExponentialBackOff
	unconfirmedTxs  map[iwallet.TransactionID]iwallet.Transaction
	transactionChan chan<- iwallet.Transaction
	msgChan         chan interface{}
	done            chan struct{}
}

// NewChainManager builds a new ChainManager from the ChainConfig.
func NewChainManager(config *ChainConfig) *ChainManager {
	backoff := expbackoff.NewExponentialBackOff()
	backoff.MaxElapsedTime = 0
	backoff.InitialInterval = time.Second

	return &ChainManager{
		client:          config.Client,
		keyManager:      config.KeyManager,
		coinType:        config.CoinType,
		logger:          config.Logger,
		db:              config.DB,
		unconfirmedTxs:  make(map[iwallet.TransactionID]iwallet.Transaction),
		transactionChan: config.TransactionChan,

		backoff: backoff,
		msgChan: make(chan interface{}),
		done:    make(chan struct{}),
	}
}

var errScanInProgress = errors.New("scan already in progress")

type scanJob struct {
	fromHeight uint64
	done       chan error
}

type saveJob struct {
	txs []iwallet.Transaction
}

type bestBlockReq struct {
	done chan iwallet.BlockInfo
}

type removeUnconfirmed struct {
	txid iwallet.TransactionID
}

// Start will begin the ChainManager process and sync up the wallet.
// This should be run in a new goroutine.
func (cm *ChainManager) Start() {
	// Here we initialize the chain, including making a couple API calls
	// to set the best height and hash. If any of that fails, we will
	// recursively call this function again with an exponential backoff.
	transactionSub, blocksSub, fromHeight, err := cm.initializeChain()
	if err != nil {
		backoffDuration := cm.backoff.NextBackOff()
		cm.logger.Errorf("Error initializing chain for coin %s: %s. Retrying in %s", cm.coinType, err, backoffDuration)
		select {
		case <-time.After(backoffDuration):
			go cm.Start()
			return
		case <-cm.done:
			return
		}
	}

	go cm.chainHandler(transactionSub, blocksSub)
	go cm.ScanTransactions(fromHeight)
}

// Stop shuts down the ChainManager
func (cm *ChainManager) Stop() {
	close(cm.done)
}

// chainHandler is the main loop for the ChainManager. It guards against concurrent
// access to critical objects and processes blocks and transactions in the order
// they come in.
func (cm *ChainManager) chainHandler(transactionSub *TransactionSubscription, blocksSub *BlockSubscription) {
	// The scan semaphore is used to ensure we have only one
	// scan job running at a time.
	scanSem := make(chan struct{}, 1)
	scanSem <- struct{}{}

	for {
		select {
		case m := <-cm.msgChan:
			switch msg := m.(type) {
			case *scanJob:
				select {
				case <-scanSem:
				default:
					msg.done <- errScanInProgress
					close(msg.done)
				}

				addrs, err := cm.keyManager.GetAddresses()
				if err != nil {
					msg.done <- err
					close(msg.done)
					continue
				}
				scanSem <- struct{}{}
				go func(addrs []iwallet.Address, job *scanJob) {
					err := cm.scanTransactions(addrs, job.fromHeight)
					msg.done <- err
					close(msg.done)
				}(addrs, msg)
			case *saveJob:
				if _, err := cm.saveTransactionsAndUtxos(msg.txs); err != nil {
					cm.logger.Errorf("Error saving incoming transaction for coin %s: %s", cm.coinType, err)
				}
			case *removeUnconfirmed:
				delete(cm.unconfirmedTxs, msg.txid)

			case *bestBlockReq:
				msg.done <- cm.best
				close(msg.done)
			}
		case tx := <-transactionSub.Out:
			cm.unconfirmedTxs[tx.ID] = tx
			cm.msgChan <- &saveJob{txs: []iwallet.Transaction{tx}}

		case blockInfo := <-blocksSub.Out:
			if len(cm.unconfirmedTxs) > 0 {
				unconfirmed := make(map[iwallet.TransactionID]iwallet.Transaction)
				for k, v := range cm.unconfirmedTxs {
					unconfirmed[k] = v
				}

				go cm.updateUnconfirmed(unconfirmed)
			}

			previousBest := cm.best
			cm.best = blockInfo
			if previousBest.BlockID.String() != blockInfo.BlockID.String() {
				done := make(chan error)
				cm.msgChan <- &scanJob{
					fromHeight: 0,
					done:       done,
				}

				err := <-done
				if err != nil {
					cm.logger.Errorf("Error scanning transactions after reorg detected, coin %s: %s", cm.coinType, err)
				}
			}

		case <-cm.done:
			transactionSub.Close()
			blocksSub.Close()
			return
		}
	}
}

func (cm *ChainManager) initializeChain() (*TransactionSubscription, *BlockSubscription, uint64, error) {
	var (
		currentBestBlock iwallet.BlockInfo
		unconfirmed      []database.TransactionRecord
	)
	err := cm.db.View(func(tx database.Tx) error {
		var record database.CoinRecord
		if err := tx.Read().Where("coin=?", cm.coinType.CurrencyCode()).First(&record).Error; err != nil {
			return err
		}
		currentBestBlock = iwallet.BlockInfo{
			BlockID: iwallet.BlockID(record.BestBlockID),
			Height:  record.BestBlockHeight,
		}
		return tx.Read().Where("coin=?", cm.coinType).Where("block_height=?", 0).Find(&unconfirmed).Error
	})
	if err != nil {
		return nil, nil, 0, err
	}

	for _, uc := range unconfirmed {
		tx, err := uc.Transaction()
		if err != nil {
			return nil, nil, 0, err
		}
		cm.unconfirmedTxs[tx.ID] = tx
	}

	blockchainInfo, err := cm.client.GetBlockchainInfo()
	if err != nil {
		return nil, nil, 0, err
	}

	cm.best = blockchainInfo

	var confirms uint64
	if currentBestBlock.Height > 0 {
		confirms, err = cm.client.GetBlockConfirmations(currentBestBlock.BlockID)
		if err != nil {
			return nil, nil, 0, err
		}
	}

	syncFrom := cm.best.Height
	if confirms == 0 {
		syncFrom = 0
	}

	addrs, err := cm.keyManager.GetAddresses()
	if err != nil {
		return nil, nil, 0, err
	}

	transactionChan, err := cm.client.SubscribeTransactions(addrs)
	if err != nil {
		return nil, nil, 0, err
	}

	blocksChan, err := cm.client.SubscribeBlocks()
	if err != nil {
		return nil, nil, 0, err
	}

	return transactionChan, blocksChan, syncFrom, nil
}

// BestBlock returns the current best block for the chain.
func (cm *ChainManager) BestBlock() iwallet.BlockInfo {
	done := make(chan iwallet.BlockInfo)
	cm.msgChan <- &bestBlockReq{done: done}

	bestBlock := <-done
	return bestBlock
}

// ScanTransactions triggers a rescan of all transactions and utxos from the provided height.
// If the rescan fails, it will be retried using an exponential backoff. If a rescan is already
// in progress this request will be ignored.
func (cm *ChainManager) ScanTransactions(fromHeight uint64) {
	backoff := expbackoff.NewExponentialBackOff()
	backoff.MaxElapsedTime = 0
	backoff.InitialInterval = time.Second

	for {
		cm.logger.Infof("Scanning transactions for coin %s", cm.coinType.CurrencyCode())
		done := make(chan error)
		cm.msgChan <- &scanJob{
			fromHeight: fromHeight,
			done:       done,
		}

		err := <-done
		if err == errScanInProgress {
			cm.logger.Warning("Scan job submitted with scan already in progress")
			return
		} else if err == nil {
			return
		}

		backoffDuration := backoff.NextBackOff()
		cm.logger.Errorf("Error scanning transactions for coin %s: %s. Retrying in %s", cm.coinType, err, backoffDuration)
		select {
		case <-time.After(backoffDuration):
			continue
		case <-cm.done:
			return
		}
	}
}

// scanTransactions will query the ChainClient for the transactions for each address. It
// tries to have no more than 20 parallel inflight requests at one time. If any returned
// transactions are new, it will extend the keychain and recursively call this method
// again to redo the query with the newly generated addresses.
func (cm *ChainManager) scanTransactions(addrs []iwallet.Address, fromHeight uint64) error {
	var (
		addrChan     = make(chan iwallet.Address, 20)
		responseChan = make(chan []iwallet.Transaction, len(addrs))
	)

	go func() {
		for _, addr := range addrs {
			addrChan <- addr
		}
		close(addrChan)
	}()

	var wg sync.WaitGroup
	wg.Add(len(addrs))
	go func() {
		for addr := range addrChan {
			go func(address iwallet.Address) {
				defer wg.Done()
				txs, err := cm.client.GetAddressTransactions(address, fromHeight)
				if err != nil {
					cm.logger.Errorf("Error fetching transactions for address %s, coin %s: %s", address, cm.coinType, err)
					return
				}
				responseChan <- txs
			}(addr)

		}
		wg.Wait()
		close(responseChan)
	}()

	var txs []iwallet.Transaction
	for resp := range responseChan {
		txs = append(txs, resp...)
	}

	newTxs, err := cm.saveTransactionsAndUtxos(txs)
	if err != nil {
		return err
	}
	// If there were any new transaction we need to extend the keychain
	// and rescan so as to detect any additional transactions for the new
	// keys.
	if newTxs > 0 {
		if err := cm.keyManager.ExtendKeychain(); err != nil {
			return err
		}
		return cm.scanTransactions(addrs, fromHeight)
	}
	return nil
}

// updateUnconfirmed will query the ChainClient to find out if any of the unconfirmed transactions
// received their first confirmation.
func (cm *ChainManager) updateUnconfirmed(unconfirmed map[iwallet.TransactionID]iwallet.Transaction) {
	type resp struct {
		txid      iwallet.TransactionID
		height    uint64
		blockTime time.Time
	}

	var (
		txidChan     = make(chan iwallet.TransactionID, 20)
		responseChan = make(chan resp, len(unconfirmed))
	)

	go func() {
		for txid := range unconfirmed {
			txidChan <- txid
		}
		close(txidChan)
	}()

	var wg sync.WaitGroup
	wg.Add(len(unconfirmed))

	go func() {
		for txid := range txidChan {
			go func(id iwallet.TransactionID) {
				defer wg.Done()
				blockInfo, err := cm.client.GetTransactionConfirmationInfo(id)
				if err != nil {
					cm.logger.Errorf("Error querying block height for transaction %s, coin %s: %s", id, cm.coinType, err)
					return
				}
				responseChan <- resp{
					txid:      id,
					height:    blockInfo.Height,
					blockTime: blockInfo.BlockTime,
				}
			}(txid)

		}
		wg.Wait()
		close(responseChan)
	}()

	var responses []resp
	for resp := range responseChan {
		responses = append(responses, resp)
	}

	var updated []iwallet.Transaction
	cm.db.Update(func(tx database.Tx) error {
		for _, resp := range responses {
			if resp.height > 0 {
				var record database.TransactionRecord
				if err := tx.Read().Where("txid=?", resp.txid.String()).First(&record).Error; err != nil {
					cm.logger.Errorf("Error updating unconfirmed transaction %s, coin %s: %s", resp.txid, cm.coinType, err)
					continue
				}
				record.BlockHeight = resp.height

				if err := tx.Save(&record); err != nil {
					cm.logger.Errorf("Error updating unconfirmed transaction %s, coin %s: %s", resp.txid, cm.coinType, err)
					continue
				}

				updated = append(updated, unconfirmed[resp.txid])

				cm.msgChan <- &removeUnconfirmed{txid: resp.txid}
			}
		}
		return nil
	})

	// Send updated transactions out to the subscriber.
	if cm.transactionChan != nil {
		for _, tx := range updated {
			cm.transactionChan <- tx
		}
	}
}

// saveTransactionsAndUtxos updates both the transactions and utxos tables in the
// database with the new transactions provided.
func (cm *ChainManager) saveTransactionsAndUtxos(newTxs []iwallet.Transaction) (int, error) {
	numNew := 0
	var newOrUpdated []iwallet.Transaction
	err := cm.db.Update(func(dbtx database.Tx) error {
		// First load all the transactions from the db.
		var savedTxs []database.TransactionRecord
		if err := dbtx.Read().Where("coin=?", cm.coinType.CurrencyCode()).Find(&savedTxs).Error; err != nil && !gorm.IsRecordNotFoundError(err) {
			return err
		}

		// Make a map out of them for easy querying.
		txMap := make(map[iwallet.TransactionID]database.TransactionRecord)
		for _, tx := range savedTxs {
			txMap[tx.TransactionID()] = tx
		}

		// For each new transaction that we are trying to save, if it already exists in the
		// database, just update the height and timestamp if necessary. If it doesn't already
		// exist then save it.
		for _, tx := range newTxs {
			savedTx, ok := txMap[tx.ID]
			if ok && savedTx.Height() != tx.Height {
				savedTx.BlockHeight = tx.Height
				if tx.BlockInfo != nil {
					savedTx.Timestamp = tx.BlockInfo.BlockTime
				}

				if err := dbtx.Save(&savedTx); err != nil {
					return err
				}

				newOrUpdated = append(newOrUpdated, tx)
			} else if !ok {
				t := time.Now()
				if tx.BlockInfo != nil {
					t = tx.BlockInfo.BlockTime
				}

				txr, err := database.NewTransactionRecord(tx, t, cm.coinType)
				if err != nil {
					return err
				}
				if err := dbtx.Save(txr); err != nil {
					return err
				}
				txMap[tx.ID] = *txr
				numNew++
				newOrUpdated = append(newOrUpdated, tx)
			}
		}

		// Next we will calculate our utxo set.
		addrs, err := cm.keyManager.GetAddresses()
		if err != nil {
			return err
		}

		addrMap := make(map[iwallet.Address]bool)
		for _, addr := range addrs {
			addrMap[addr] = true
		}

		utxos := make(map[string]database.UtxoRecord)

		// For each transaction, check to see if an output address matches one
		// of our addresses. If so, add it to the utxo map.
		for _, rec := range txMap {
			tx, err := rec.Transaction()
			if err != nil {
				return err
			}

			for _, to := range tx.To {
				if addrMap[to.Address] {
					t := time.Now()
					if tx.BlockInfo != nil {
						t = tx.BlockInfo.BlockTime
					}

					outpoint := hex.EncodeToString(to.ID)
					utxos[outpoint] = database.UtxoRecord{
						Outpoint:  outpoint,
						Height:    tx.Height,
						Timestamp: t,
						Coin:      cm.coinType.CurrencyCode(),
					}
				}
			}
		}

		// Now we iterate over the transactions again, if any of the inputs
		// spend one of our outputs we remove it from our utxo map.
		//
		// After this loop the remaining set should contain all of our utxos.
		for _, rec := range txMap {
			tx, err := rec.Transaction()
			if err != nil {
				return err
			}

			for _, from := range tx.From {
				outpoint := hex.EncodeToString(from.ID)
				if _, ok := utxos[outpoint]; ok {
					delete(utxos, outpoint)
				}
			}
		}

		// Now lets load current utxos from the database. We want to delete any utxos
		// from the db that are not in our calculated set.
		var savedUtxos []database.UtxoRecord
		if err := dbtx.Read().Where("coin=?", cm.coinType.CurrencyCode()).Find(&savedUtxos).Error; err != nil && !gorm.IsRecordNotFoundError(err) {
			return err
		}

		savedUtxoMap := make(map[string]bool)
		for _, utxo := range savedUtxos {
			savedUtxoMap[utxo.Outpoint] = true
		}

		for outpoint := range savedUtxoMap {
			if _, ok := utxos[outpoint]; !ok {
				if err := dbtx.Delete("outpoint", outpoint, &database.UtxoRecord{}); err != nil {
					return err
				}
			}
		}

		// Finally save each utxo to the database.
		for _, utxo := range utxos {
			if err := dbtx.Save(&utxo); err != nil {
				return err
			}
		}

		return nil
	})

	// Send any new or updated transactions out to the subscriber.
	if cm.transactionChan != nil {
		for _, tx := range newOrUpdated {
			cm.transactionChan <- tx
		}
	}

	return numNew, err
}
