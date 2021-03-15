// Copyright (c) 2020-2021 Simple Ledger, Inc.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package indexers

import (
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/gcash/bchd/blockchain"
	"github.com/gcash/bchd/chaincfg/chainhash"
	"github.com/gcash/bchd/database"
	"github.com/gcash/bchd/wire"
	"github.com/gcash/bchutil"
	"github.com/simpleledgerinc/goslp/v1parser"
)

const (
	// groupTokenIndexName is the human-readable name for the index.
	groupTokenIndexName = "group token index"
)

var (
	// groupTxIndexKey is the key of the transaction index and the db bucket used
	// to house it.
	groupTxIndexKey = []byte("grouptxbyhashidx")

	// groupIDByHashIndexBucketName is the name of the db bucket used to house
	// the group id (bytes) -> group id (uint32) index.
	groupIDByHashIndexBucketName = []byte("groupidbyhashidx")

	// groupInfoByIDIndexBucketName is the name of the db bucket used to house
	// the group id -> group metadata info index.
	groupInfoByIDIndexBucketName = []byte("groupinfobyididx")

	// errNoGroupMetadataEntry is an error that indicates a requested entry does
	// not exist in the token metadata index.
	errNoGroupMetadataEntry = errors.New("no entry in the token metadata db")

	// errNoGroupIDHashEntry is an error that indicates a requested entry does
	// not exist in the group id by hash index.
	errNoGroupIDHashEntry = errors.New("no entry in the group id by hash db")
)

// -----------------------------------------------------------------------------
// The slp index consists of an entry for every slp-like transaction in the main
// chain.  In order to significantly optimize the space requirements a separate
// index which provides an internal mapping between each TokenID that has been
// indexed and a unique ID for use within the hash to location mappings.  The ID
// is simply a sequentially incremented uint32.  This is useful because it is
// only 4 bytes versus 32 bytes hashes and thus saves a ton of space in the
// index.
//
// There are three buckets used in total.  The first bucket maps the TokenID
// hash to the specific uint32 ID location.  The second bucket maps the
// uint32 of each TokenID to the actual TokenID hash and the third maps that
// unique uint32 ID back to the TokenID hash.
//
//
// The serialized format for keys and values in the TokenID hash to ID bucket is:
//   <hash> = <ID>
//
//   Field           Type              Size
//   TokenID hash    chainhash.Hash    32 bytes
//   ID              uint32            4 bytes
//   -----
//   Total: 36 bytes
//
// The serialized format for keys and values in the ID to TokenID hash bucket is:
//   <ID> = <group id txid><mint baton hash><uint32>
//
//   Field            					Type              Size
//   ID               					uint32            4 bytes
//   TokenID hash                   	chainhash.Hash    32 bytes
//   slp version	    				uint16            2 bytes
//   Mint baton hash (or nft group id)  chainhash.Hash    32 bytes (optional)
//   Mint baton vout  					uint32			  4 bytes  (optional)
//   -----
//   Max: 74 bytes max
//
// The serialized format for the keys and values in the slp index bucket is:
//
//   <txhash> = <group id><slp version><slp op_return>
//
//   Field           	Type              Size
//   txhash          	chainhash.Hash    32 bytes
//   group id        	uint32            4 bytes
//   slp version	    uint16            2 bytes
//	 op_return			[]bytes			  typically <220 bytes
//   -----
//   Max: 258 bytes (if op_return is limited to 220 bytes)
//	 Min: 43 bytes (4 + 2 + 37)
//
//   NOTE: The minimum possible slp op_return is 37 bytes, this is empty genesis
//
// -----------------------------------------------------------------------------

// GroupMetadata is used to hold the unmarshalled data parsed from the group id index
type GroupMetadata struct {
	TokenID       *chainhash.Hash
	SlpVersion    v1parser.TokenType
	NftGroupID    *chainhash.Hash
	MintBatonHash *chainhash.Hash
	MintBatonVout uint32
}

// dbPutGroupIDIndexEntry uses an existing database transaction to update or add
// the index entries for the hash to id and id to hash mappings for the provided
// values.
func dbPutGroupIDIndexEntry(dbTx database.Tx, id uint32, metadata *GroupMetadata) error {
	// Serialize the height for use in the index entries.
	var serializedID [4]byte
	byteOrder.PutUint32(serializedID[:], id)

	// Add the group id by token hash mapping to the index.
	meta := dbTx.Metadata()
	hashIndex := meta.Bucket(groupIDByHashIndexBucketName)
	if err := hashIndex.Put(metadata.TokenID[:], serializedID[:]); err != nil {
		return err
	}

	// Add or update token metadata by uint32 tokenID mapping to the index.
	tmIndex := meta.Bucket(groupInfoByIDIndexBucketName)
	GroupMetadata := make([]byte, 32+2+32+4)

	copy(GroupMetadata[0:], metadata.TokenID[:])

	byteOrder.PutUint16(GroupMetadata[32:], uint16(metadata.SlpVersion))

	if metadata.NftGroupID != nil {
		copy(GroupMetadata[34:], metadata.NftGroupID[:])
		GroupMetadata = GroupMetadata[:66]
	} else if metadata.MintBatonHash != nil {
		copy(GroupMetadata[34:], metadata.MintBatonHash[:])
		byteOrder.PutUint32(GroupMetadata[66:], metadata.MintBatonVout)
	} else {
		GroupMetadata = GroupMetadata[:34]
	}

	if metadata.NftGroupID == nil && metadata.SlpVersion == v1parser.TokenTypeNft1Child41 {
		return fmt.Errorf("missing nft group id for NFT child %v", id)
	}

	return tmIndex.Put(serializedID[:], GroupMetadata)
}

// dbFetchGroupIDByHash uses an existing database transaction to retrieve the
// group id for the provided hash from the index.
func dbFetchGroupIDByHash(dbTx database.Tx, hash *chainhash.Hash) (uint32, error) {
	hashIndex := dbTx.Metadata().Bucket(groupIDByHashIndexBucketName)
	serializedID := hashIndex.Get(hash[:])
	if serializedID == nil {
		return 0, errNoGroupIDHashEntry
	}
	return byteOrder.Uint32(serializedID), nil
}

// dbFetchGroupMetadataBySerializedID uses an existing database transaction to
// retrieve the hash for the provided serialized group id from the index.
func dbFetchGroupMetadataBySerializedID(dbTx database.Tx, serializedID []byte) (*GroupMetadata, error) {
	idIndex := dbTx.Metadata().Bucket(groupInfoByIDIndexBucketName)
	serializedData := idIndex.Get(serializedID)
	if serializedData == nil {
		return nil, errNoGroupMetadataEntry
	}

	tokenIDHash, err := chainhash.NewHash(serializedData[0:32])
	if err != nil {
		return nil, fmt.Errorf("failed to create hash from %s", hex.EncodeToString(serializedData[0:32]))
	}
	if len(serializedData) < 34 {
		return nil, fmt.Errorf("missing token version type for token metadata of group id %v", tokenIDHash)
	}

	slpVersion := v1parser.TokenType(byteOrder.Uint16(serializedData[32:34]))

	var (
		mintBatonHash *chainhash.Hash
		mintBatonVout uint32
		nft1GroupID   *chainhash.Hash
	)
	if len(serializedData) == 70 {
		if slpVersion == v1parser.TokenTypeNft1Child41 {
			return nil, errors.New("cannot have this stored data length with nft1 child, drop and add GroupIndex")
		}
		var err error
		mintBatonHash, err = chainhash.NewHash(serializedData[34:66])
		if err != nil {
			return nil, fmt.Errorf("could not create mint baton hash with data: %s", hex.EncodeToString(serializedData[34:66]))
		}
		mintBatonVout = byteOrder.Uint32(serializedData[66:])
	} else if len(serializedData) == 66 {
		if slpVersion != v1parser.TokenTypeNft1Child41 {
			return nil, errors.New("cannot have this stored data length if not nft1 child, drop and add GroupIndex")
		}
		var err error
		nft1GroupID, err = chainhash.NewHash(serializedData[34:])
		if err != nil {
			return nil, fmt.Errorf("could not create nft group id hash with data: %s", hex.EncodeToString(serializedData[34:]))
		}
	}

	tm := &GroupMetadata{
		TokenID:       tokenIDHash,
		NftGroupID:    nft1GroupID,
		MintBatonHash: mintBatonHash,
		MintBatonVout: mintBatonVout,
	}
	return tm, nil
}

// dbFetchGroupMetadataByID uses an existing database transaction to retrieve the
// hash for the provided group id from the index.
func dbFetchGroupMetadataByID(dbTx database.Tx, id uint32) (*GroupMetadata, error) {
	var serializedID [4]byte
	byteOrder.PutUint32(serializedID[:], id)
	return dbFetchGroupMetadataBySerializedID(dbTx, serializedID[:])
}

type dbGroupIndexEntry struct {
	tx             *wire.MsgTx
	slpMsg         v1parser.ParseResult
	tokenIDHash    *chainhash.Hash
	slpMsgPkScript []byte
}

// dbPutGroupIndexEntry uses an existing database transaction to update the
// transaction index given the provided serialized data that is expected to have
// been serialized putGroupIndexEntry.
func dbPutGroupIndexEntry(idx *GroupIndex, dbTx database.Tx, entryInfo *dbGroupIndexEntry) error {
	txHash := entryInfo.tx.TxHash()

	// get current tokenID uint32 for the tokenID hash, add new if needed
	tokenID, err := dbFetchGroupIDByHash(dbTx, entryInfo.tokenIDHash)
	if err != nil {
		tokenID = idx.curTokenID + 1
	}

	var (
		GroupMetadataNeedsUpdated bool   = false
		mintBatonVout             uint32 = 0
		mintBatonHash             *chainhash.Hash
		nft1GroupID               *chainhash.Hash
	)

	switch entry := entryInfo.slpMsg.(type) {
	case *v1parser.SlpGenesis:
		idx.curTokenID++
		GroupMetadataNeedsUpdated = true
		if entry.MintBatonVout > 1 {
			mintBatonVout = uint32(entry.MintBatonVout)
			mintBatonHash = &txHash
		} else if entry.TokenType() == v1parser.TokenTypeNft1Child41 {
			if len(entryInfo.tx.TxIn) < 1 {
				return errors.New("entryInfo transaction has no inputs")
			}
			groupTokenEntry, err := dbFetchGroupIndexEntry(dbTx, &entryInfo.tx.TxIn[0].PreviousOutPoint.Hash)
			if err != nil {
				return fmt.Errorf("failed to fetch nft parent group id %v: %v", entryInfo.tx.TxIn[0].PreviousOutPoint.Hash, err)
			}
			nft1GroupID = &groupTokenEntry.TokenIDHash
		}
	case *v1parser.SlpMint:
		GroupMetadataNeedsUpdated = true
		if entry.MintBatonVout > 1 {
			mintBatonVout = uint32(entry.MintBatonVout)
			mintBatonHash = &txHash
		}
	}

	// maybe update token metadata
	if GroupMetadataNeedsUpdated {
		err = dbPutGroupIDIndexEntry(dbTx, tokenID,
			&GroupMetadata{
				TokenID:       entryInfo.tokenIDHash,
				SlpVersion:    entryInfo.slpMsg.TokenType(),
				MintBatonHash: mintBatonHash,
				MintBatonVout: mintBatonVout,
				NftGroupID:    nft1GroupID,
			})
		if err != nil {
			return fmt.Errorf("failed to update db for group id: %v, this should never happen", entryInfo.tokenIDHash)
		}
	}

	// err = idx.cache.AddGroupTxEntry(&txHash, GroupTxEntry{
	// 	TokenID:        tokenID,
	// 	TokenIDHash:    *entryInfo.tokenIDHash,
	// 	SlpVersionType: entryInfo.slpMsg.TokenType(),
	// 	SlpOpReturn:    entryInfo.slpMsgPkScript,
	// })
	// if err != nil {
	// 	log.Criticalf("AddGroupTxEntry in dbPutGroupIndexEntry failed: ", err)
	// }

	target := make([]byte, 4+2+len(entryInfo.slpMsgPkScript))
	byteOrder.PutUint32(target[:], tokenID)
	byteOrder.PutUint16(target[4:], uint16(entryInfo.slpMsg.TokenType()))
	copy(target[6:], entryInfo.slpMsgPkScript)
	GroupIndex := dbTx.Metadata().Bucket(groupTxIndexKey)
	return GroupIndex.Put(txHash[:], target)
}

// GroupTxEntry is a valid slp token stored in the slp index
type GroupTxEntry struct {
	TokenID        uint32
	TokenIDHash    chainhash.Hash
	SlpVersionType v1parser.TokenType
	SlpOpReturn    []byte
}

// dbFetchGroupIndexEntry uses an existing database transaction to fetch the serialized slp
// index entry for the provided transaction hash.  When there is no entry for the provided hash,
// nil will be returned for the both the entry and the error.
func dbFetchGroupIndexEntry(dbTx database.Tx, txHash *chainhash.Hash) (*GroupTxEntry, error) {
	// Load the record from the database and return now if it doesn't exist.
	GroupIndex := dbTx.Metadata().Bucket(groupTxIndexKey)
	serializedData := GroupIndex.Get(txHash[:])
	if len(serializedData) == 0 {
		return nil, fmt.Errorf("slp entry does not exist %v", txHash)
	}

	// Ensure the serialized data has enough bytes to properly deserialize.
	// The minimum possible entry size is 4 + 2 + 37 = 43, which is an empty GENESIS slp OP_RETURN.
	if len(serializedData) < 43 {
		return nil, database.Error{
			ErrorCode: database.ErrCorruption,
			Description: fmt.Sprintf("corrupt slp index "+
				"entry for %s", txHash),
		}
	}
	entry := &GroupTxEntry{
		TokenID: byteOrder.Uint32(serializedData[0:4]),
	}
	GroupMetadata, err := dbFetchGroupMetadataByID(dbTx, entry.TokenID)
	if err != nil {
		return nil, err
	}
	entry.TokenIDHash = *GroupMetadata.TokenID
	entry.SlpVersionType = v1parser.TokenType(byteOrder.Uint16(serializedData[4:6]))
	entry.SlpOpReturn = serializedData[6:]
	return entry, nil
}

// dbRemoveGroupIndexEntries uses an existing database transaction to remove the
// latest slp transaction entry for every transaction in the passed block.
//
// This method should only be called by DisconnectBlock()
//
func dbRemoveGroupIndexEntries(dbTx database.Tx, block *bchutil.Block) error {
	// toposort and reverse order so we can unwind slp token metadata state if needed
	txs := TopologicallySortTxs(block.Transactions())
	var txsRev []*wire.MsgTx
	for i := len(txs) - 1; i >= 0; i-- {
		txsRev = append(txsRev, txs[i])
	}

	// this method should only be called after a topological sort
	dbRemoveGroupIndexEntry := func(dbTx database.Tx, txHash *chainhash.Hash) error {
		GroupIndex := dbTx.Metadata().Bucket(groupTxIndexKey)
		serializedData := GroupIndex.Get(txHash[:])
		if len(serializedData) == 0 {
			return nil
		}

		// NOTE: We don't need to worry about updating mint baton token metadata here since it isn't
		// relied upon for the purpose of validation.  If a mint boton double spend occurs
		// then the token metadata record will be updated when ConnectBlock is called.

		return GroupIndex.Delete(txHash[:])
	}

	for _, tx := range txsRev {
		hash := tx.TxHash()
		err := dbRemoveGroupIndexEntry(dbTx, &hash)
		if err != nil {
			return err
		}
	}

	return nil
}

// GroupIndex implements a transaction by hash index.  That is to say, it supports
// querying all transactions by their hash.
type GroupIndex struct {
	db         database.DB
	curTokenID uint32
	config     *GroupConfig
	cache      *SlpCache
}

// Ensure the GroupIndex type implements the Indexer interface.
var _ Indexer = (*GroupIndex)(nil)

// Init initializes the hash-based slp transaction index.  In particular, it finds
// the highest used group id and stores it for later use when a new token has been
// created.
//
// This is part of the Indexer interface.
func (idx *GroupIndex) Init() error {
	// Find the latest known group id field for the internal group id
	// index and initialize it.  This is done because it's a lot more
	// efficient to do a single search at initialize time than it is to
	// write another value to the database on every update.
	err := idx.db.View(func(dbTx database.Tx) error {
		var highestKnown, nextUnknown uint32
		testTokenID := uint32(1)
		increment := uint32(1)
		for {
			md, err := dbFetchGroupMetadataByID(dbTx, testTokenID)
			if err != nil {
				if md != nil {
					return fmt.Errorf("could not init slp index: %v", err)
				}
				nextUnknown = testTokenID
				break
			}

			highestKnown = testTokenID
			testTokenID += increment
		}
		log.Tracef("Forward scan (highest known %d, next unknown %d)",
			highestKnown, nextUnknown)

		idx.curTokenID = highestKnown
		return nil
	})

	if err != nil {
		return err
	}

	log.Infof("Current number of slp tokens in index: %v", idx.curTokenID)
	return nil
}

// StartBlock is used to indicate the proper start block for the index manager.
//
// This is part of the Indexer interface.
func (idx *GroupIndex) StartBlock() (*chainhash.Hash, int32) {
	return idx.config.StartHash, idx.config.StartHeight
}

// Migrate is only provided to satisfy the Indexer interface as there is nothing to
// migrate this index.
//
// This is part of the Indexer interface.
func (idx *GroupIndex) Migrate(db database.DB, interrupt <-chan struct{}) error {
	// Nothing to do.
	return nil
}

// Key returns the database key to use for the index as a byte slice.
//
// This is part of the Indexer interface.
func (idx *GroupIndex) Key() []byte {
	return groupTxIndexKey
}

// Name returns the human-readable name of the index.
//
// This is part of the Indexer interface.
func (idx *GroupIndex) Name() string {
	return groupTokenIndexName
}

// Create is invoked when the indexer manager determines the index needs
// to be created for the first time.  It creates the buckets for the hash-based
// transaction index and the internal group id and token metadata indexes.
//
// This is part of the Indexer interface.
func (idx *GroupIndex) Create(dbTx database.Tx) error {
	meta := dbTx.Metadata()
	if _, err := meta.CreateBucket(groupIDByHashIndexBucketName); err != nil {
		return err
	}
	if _, err := meta.CreateBucket(groupInfoByIDIndexBucketName); err != nil {
		return err
	}
	_, err := meta.CreateBucket(groupTxIndexKey)
	return err
}

// ConnectBlock is invoked by the index manager when a new block has been
// connected to the main chain.  This indexer adds a hash-to-transaction mapping
// for every transaction in the passed block.
//
// This is part of the Indexer interface.
func (idx *GroupIndex) ConnectBlock(dbTx database.Tx, block *bchutil.Block, stxos []blockchain.SpentTxOut) error {

	putTxIndexEntry := func(tx *wire.MsgTx, slpMsg v1parser.ParseResult, tokenIDHash *chainhash.Hash) error {
		if len(tx.TxOut) < 1 {
			return fmt.Errorf("transaction has no outputs %v", tx.TxHash())
		}

		return dbPutGroupIndexEntry(idx, dbTx, &dbGroupIndexEntry{
			tx:             tx,
			slpMsg:         slpMsg,
			tokenIDHash:    tokenIDHash,
			slpMsgPkScript: tx.TxOut[0].PkScript,
		})
	}

	for _, tx := range block.Transactions() {
		_, err := CheckGroupTx(tx.MsgTx(), putTxIndexEntry)
		if err != nil {
			log.Critical(err)
			return err
		}
	}

	return nil
}

func (idx *GroupIndex) checkBurnedInputForMintBaton(dbTx database.Tx, burn *BurnedInput) (bool, error) {

	// we can skip nft children since they don't have mint batons
	if burn.SlpMsg.TokenType() == v1parser.TokenTypeNft1Child41 {
		return false, nil
	}

	// check if input is the mint baton from either Genesis or Mint parent data
	switch msg := burn.SlpMsg.(type) {
	case *v1parser.SlpGenesis:
		if msg.MintBatonVout != int(burn.TxInput.PreviousOutPoint.Index) {
			return false, nil
		}
	case *v1parser.SlpMint:
		if msg.MintBatonVout != int(burn.TxInput.PreviousOutPoint.Index) {
			return false, nil
		}
	default:
		return false, nil
	}

	// double-check this burned mint baton was a valid slp token
	if burn.Entry == nil {
		return false, nil
	}

	err := dbPutGroupIDIndexEntry(dbTx, burn.Entry.TokenID,
		&GroupMetadata{
			TokenID:       &burn.Entry.TokenIDHash,
			SlpVersion:    burn.Entry.SlpVersionType,
			MintBatonHash: nil,
			MintBatonVout: 0,
			NftGroupID:    nil,
		},
	)
	if err != nil {
		return false, fmt.Errorf("could not update token metadata for group id: %v", burn.Entry.TokenIDHash)
	}

	return true, nil
}

// AddGroupTxIndexEntryHandler provides a function interface for CheckGroupTx
type AddGroupTxIndexEntryHandler func(*wire.MsgTx, v1parser.ParseResult, *chainhash.Hash) error

// CheckGroupTx checks a transaction for validity and adds valid transactions to the db
func CheckGroupTx(tx *wire.MsgTx, putTxIndexEntry AddGroupTxIndexEntryHandler) (bool, error) {
	return false, nil
}

// DisconnectBlock is invoked by the index manager when a block has been
// disconnected from the main chain.  This indexer removes the
// hash-to-transaction mapping for every transaction in the block.
//
// This is part of the Indexer interface.
func (idx *GroupIndex) DisconnectBlock(dbTx database.Tx, block *bchutil.Block, stxos []blockchain.SpentTxOut) error {

	// Remove all of the transactions in the block from the index.
	if err := dbRemoveGroupIndexEntries(dbTx, block); err != nil {
		return err
	}

	return nil
}

// GetGroupIndexEntry returns a serialized slp index entry for the provided transaction hash
// from the slp index.  The slp index entry can in turn be used to quickly discover
// additional slp information about the transaction. When there is no entry for the provided hash, nil
// will be returned for the both the entry and the error, which would mean the transaction is invalid
//
// This function is safe for concurrent access.
func (idx *GroupIndex) GetGroupIndexEntry(dbTx database.Tx, hash *chainhash.Hash) (*GroupTxEntry, error) {
	// if entry, ok := idx.cache.GetGroupTxEntry(hash); ok {
	// 	log.Debugf("using slp txn entry cache for txid %v", hash)
	// 	return &entry, nil
	// }

	// fallback to fetch entry from db
	entry, err := dbFetchGroupIndexEntry(dbTx, hash)
	if err != nil {
		return nil, err
	}

	// err = idx.cache.AddGroupTxEntry(hash, *entry)
	// if err != nil {
	// 	log.Criticalf("AddGroupTxEntry in GetGroupIndexEntry failed: ", err)
	// }
	return entry, nil
}

// GetGroupMetadata fetches token metadata properties from an GroupIndexEntry
func (idx *GroupIndex) GetGroupMetadata(dbTx database.Tx, entry *GroupTxEntry) (*GroupMetadata, error) {
	// if tm, ok := idx.cache.GetGroupMetadata(&entry.TokenIDHash); ok {
	// 	log.Debugf("using token metadata cache for %s", hex.EncodeToString(entry.TokenIDHash[:]))
	// 	return &tm, nil
	// }

	if entry.TokenID == 0 {
		id, err := dbFetchGroupIDByHash(dbTx, &entry.TokenIDHash)
		if err != nil {
			log.Debugf("db is missing tokenID %s", hex.EncodeToString(entry.TokenIDHash[:]))
			return nil, err
		}
		entry.TokenID = id
	}

	// fallback to fetch token metadata from db
	tm, err := dbFetchGroupMetadataByID(dbTx, entry.TokenID)
	if err != nil {
		return nil, err
	}

	// err = idx.cache.AddTempGroupMetadata(*tm)
	// if err != nil {
	// 	log.Criticalf("AddTempGroupMetadata in GetGroupMetadata failed: ", err)
	// }
	return tm, nil
}

// // AddPotentialSlpEntries checks if a transaction is slp valid and then will add a
// // new GroupIndexEntry to the shared cache of valid slp transactions.
// //
// // This method should be used to assess slp validity of newly received mempool items and also in rpc
// // client subscriber methods that return notifications for both mempool and block events to prevent
// // any possibility of a race conditions with manageSlpEntryCache.
// func (idx *GroupIndex) AddPotentialSlpEntries(dbTx database.Tx, msgTx *wire.MsgTx) (bool, error) {

// 	getGroupIndexEntry := func(txiHash *chainhash.Hash) (*GroupTxEntry, error) {
// 		entry, err := idx.GetGroupIndexEntry(dbTx, txiHash)
// 		if entry != nil {
// 			return entry, nil
// 		}

// 		return nil, err
// 	}

// 	putTxIndexEntry := func(tx *wire.MsgTx, slpMsg v1parser.ParseResult, tokenIDHash *chainhash.Hash) error {
// 		scriptPubKey := tx.TxOut[0].PkScript
// 		hash := tx.TxHash()

// 		// add item to slp txn cache
// 		idx.cache.AddMempoolGroupTxEntry(&hash, GroupTxEntry{
// 			TokenID:        0,
// 			TokenIDHash:    *tokenIDHash,
// 			SlpVersionType: slpMsg.TokenType(),
// 			SlpOpReturn:    scriptPubKey,
// 		})

// 		// add or update token metadata cache
// 		switch t := slpMsg.(type) {
// 		case *v1parser.SlpGenesis:
// 			// add genesis token metadata to cache
// 			log.Debugf("adding slp genesis token metadata for %v", hex.EncodeToString(tokenIDHash[:]))
// 			tm := GroupMetadata{
// 				TokenID:    tokenIDHash,
// 				SlpVersion: slpMsg.TokenType(),
// 			}
// 			if slpMsg.TokenType() == v1parser.TokenTypeNft1Child41 {
// 				// handle special case for NFT child with group id
// 				err := idx.db.View(func(dbTx database.Tx) error {
// 					entry, err := idx.GetGroupIndexEntry(dbTx, &tx.TxIn[0].PreviousOutPoint.Hash)
// 					if err != nil {
// 						return fmt.Errorf("nft child genesis has invalid group in txn %v: %v", tx.TxHash(), err)
// 					}
// 					tm.NftGroupID = &entry.TokenIDHash
// 					if tm.NftGroupID == nil {
// 						return fmt.Errorf("nft child group ID could not be resolved in txn %v", tx.TxHash())
// 					}
// 					return nil
// 				})
// 				if err != nil {
// 					log.Debugf("AddPotentialSlpEntries: %v", err)
// 				}
// 			} else if t.MintBatonVout > 1 {
// 				hash := tx.TxHash()
// 				tm.MintBatonHash = &hash
// 				tm.MintBatonVout = uint32(t.MintBatonVout)
// 			}
// 			err := idx.cache.AddTempGroupMetadata(tm)
// 			if err != nil {
// 				log.Criticalf("AddTempGroupMetadata in AddPotentialSlpEntries failed for Genesis: ", err)
// 			}
// 		case *v1parser.SlpMint:
// 			// update the mint baton location
// 			log.Debugf("adding slp mint token metadata for %v", hex.EncodeToString(tokenIDHash[:]))
// 			err := idx.db.View(func(dbTx database.Tx) error {
// 				hash := tx.TxHash()
// 				entry, err := idx.GetGroupIndexEntry(dbTx, &hash)
// 				tm, err := idx.GetGroupMetadata(dbTx, entry)
// 				if err != nil {
// 					return fmt.Errorf("could not retreive token metadata for mint txn %v: %v", hash, err)
// 				}
// 				if t.MintBatonVout > 1 {
// 					hash := tx.TxHash()
// 					tm.MintBatonHash = &hash
// 					tm.MintBatonVout = uint32(t.MintBatonVout)
// 					err := idx.cache.AddTempGroupMetadata(*tm)
// 					if err != nil {
// 						log.Criticalf("AddTempGroupMetadata in AddPotentialSlpEntries failed for Mint: ", err)
// 					}
// 				} else {
// 					return fmt.Errorf("invalid mint baton for mint txn %v: %v", hash, err)
// 				}
// 				return nil
// 			})
// 			if err != nil {
// 				log.Debugf("AddPotentialSlpEntries: %v", err)
// 			}
// 		}
// 		return nil
// 	}

// 	valid, _, err := CheckGroupTx(msgTx, getGroupIndexEntry, putTxIndexEntry)

// 	return valid, err
// }

// RemoveMempoolSlpTxs removes a list of transactions from the temporary cache that holds
// both mempool and recently queried GroupIndexEntries
func (idx *GroupIndex) RemoveMempoolSlpTxs(txs []*bchutil.Tx) {
	idx.cache.RemoveMempoolSlpTxItems(txs)
}

// GroupConfig provides the proper starting height and hash
type GroupConfig struct {
	StartHash    *chainhash.Hash
	StartHeight  int32
	AddrPrefix   string
	MaxCacheSize int
}

// NewGroupIndex returns a new instance of an indexer that is used to create a
// mapping of the hashes of all slp transactions in the blockchain to the respective
// group id, and token metadata.
//
// It implements the Indexer interface which plugs into the IndexManager that in
// turn is used by the blockchain package.  This allows the index to be
// seamlessly maintained along with the chain.
func NewGroupIndex(db database.DB, cfg *GroupConfig) *GroupIndex {
	return &GroupIndex{
		db:     db,
		config: cfg,
		cache:  InitSlpCache(cfg.MaxCacheSize),
	}
}

// dropGroupIndexes drops the internal group id index.
func dropGroupIndexes(db database.DB) error {
	return db.Update(func(dbTx database.Tx) error {
		meta := dbTx.Metadata()
		err := meta.DeleteBucket(groupIDByHashIndexBucketName)
		if err != nil {
			return err
		}

		return meta.DeleteBucket(groupInfoByIDIndexBucketName)
	})
}

// DropGroupIndex drops the transaction index from the provided database if it
// exists.  Since the address index relies on it, the address index will also be
// dropped when it exists.
func DropGroupIndex(db database.DB, interrupt <-chan struct{}) error {
	return dropIndex(db, groupTxIndexKey, groupTokenIndexName, interrupt)
}
