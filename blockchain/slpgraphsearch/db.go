package slpgraphsearch

import (
	"bytes"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/gcash/bchd/chaincfg/chainhash"
	"github.com/gcash/bchd/wire"
	"github.com/simpleledgerinc/goslp"
)

// Db manages slp token graphs for graph search and TODO: recently queried items
type Db struct {
	sync.RWMutex
	db    map[chainhash.Hash]*TokenGraph
	State uint32 // atomic, 0 = initial load incomplete, 1 = initial load complete, 2 = block found after load completed
}

// NewDb creates a new instance of SlpCache
func NewDb() *Db {
	return &Db{
		db:    make(map[chainhash.Hash]*TokenGraph),
		State: 0,
	}
}

// SetGsState sets the internal graph search state
func (gs *Db) SetGsState(desiredState uint32) error {
	state := atomic.LoadUint32(&gs.State)
	if state == desiredState-1 {
		atomic.AddUint32(&gs.State, desiredState)
	} else if state != desiredState {
		return errors.New("invalid state change")
	}
	return nil
}

// AddTxn adds a transaction to the graph search database
func (gs *Db) AddTxn(msgTx *wire.MsgTx) error {
	tokenIDBuf, err := goslp.GetSlpTokenID(msgTx)
	if err != nil {
		return err
	}
	tokenID, err := chainhash.NewHash(tokenIDBuf)
	if err != nil {
		return err
	}

	tg := gs.getTokenGraph(tokenID)
	err = tg.addTxn(msgTx)
	if err != nil {
		return err
	}

	return nil

}

// Find performs a graph search for a given transaction hash
func (gs *Db) Find(hash *chainhash.Hash, tokenID *chainhash.Hash, validityCache *map[chainhash.Hash]struct{}) ([][]byte, error) {

	// get token graph
	tokenGraph := gs.getTokenGraph(tokenID)
	if tokenGraph == nil {
		return nil, fmt.Errorf("graph search graph is missing for token ID %v", tokenID)
	}

	seen := make(map[chainhash.Hash]struct{})
	txdata := make([][]byte, tokenGraph.size())
	i := 0

	// check client validity cache transactions are valid
	for hash := range *validityCache {
		if txn := (*tokenGraph).getTxn(&hash); txn == nil {
			return nil, fmt.Errorf("client provided validity cache with hash %v that is not in the token graph", hash)
		}
	}

	// perform the recursive graph search
	err := gs.findInternal(hash, tokenGraph, &seen, validityCache, &txdata, &i)
	if err != nil {
		return nil, err
	}

	// TODO: Do an integrity check before returning results to client!

	return txdata[0:i], nil
}

func (gs *Db) findInternal(hash *chainhash.Hash, tokenGraph *TokenGraph, seen *map[chainhash.Hash]struct{}, validityCache *map[chainhash.Hash]struct{}, txdata *[][]byte, counter *int) error {

	// check if txn is valid slp
	txMsg := tokenGraph.getTxn(hash)
	if txMsg == nil {
		return fmt.Errorf("txn %v not in token graph, implies invalid slp", hash)
	}

	// check seen list
	if _, ok := (*seen)[*hash]; ok {
		return fmt.Errorf("txn %v already seen in graph search", hash)
	}
	(*seen)[*hash] = struct{}{}

	// add txn buffer to results
	txBuf := bytes.NewBuffer(make([]byte, 0, txMsg.SerializeSize()))
	if err := txMsg.Serialize(txBuf); err != nil {
		return err
	}
	(*txdata)[*counter] = txBuf.Bytes()
	(*counter)++

	// check exclude txids here, don't return with error
	if _, ok := (*validityCache)[*hash]; ok {
		//gs.logger.Debugf("skipping valid slp txn provided by client exclude list for %v", hash)
		return nil
	}

	// loop through inputs and recurse
	for _, txn := range txMsg.TxIn {
		err := gs.findInternal(&txn.PreviousOutPoint.Hash, tokenGraph, seen, validityCache, txdata, counter)
		if err != nil {
			//*logger.Debugf("%v", err)
			continue
		}
	}
	return nil
}

// getTokenGraph gets a token graph item from the db
func (gs *Db) getTokenGraph(tokenID *chainhash.Hash) *TokenGraph {

	gs.RLock()
	if tg, ok := gs.db[*tokenID]; ok {
		gs.RUnlock()
		return tg
	}
	gs.RUnlock()

	gs.Lock()
	defer gs.Unlock()

	if tg, ok := gs.db[*tokenID]; ok {
		return tg
	}

	item := newTokenGraph(tokenID)
	gs.db[*tokenID] = item
	return item
}
