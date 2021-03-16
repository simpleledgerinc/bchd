// Copyright (c) 2020-2021 Simple Ledger, Inc.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package indexers

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/gcash/bchd/blockchain"
	"github.com/gcash/bchd/chaincfg/chainhash"
	"github.com/gcash/bchd/database"
	"github.com/gcash/bchd/txscript"
	"github.com/gcash/bchd/wire"
	"github.com/gcash/bchutil"
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
	groupIDByHashIndexBucketName = []byte("groupidbybytesidx")

	// groupMetadataByIDIndexBucketName is the name of the db bucket used to house
	// the group id -> group info index (currently only the group id bytes).
	groupMetadataByIDIndexBucketName = []byte("groupinfobyididx")

	// errNoGroupMetadataEntry is an error that indicates a requested entry does
	// not exist in the token metadata index.
	errNoGroupMetadataEntry = errors.New("no entry in the token metadata db")

	// errNoGroupIDHashEntry is an error that indicates a requested entry does
	// not exist in the group id by hash index.
	errNoGroupIDHashEntry = errors.New("no entry in the group id by hash db")
)

// -----------------------------------------------------------------------------
// The group index consists of an entry for every group-like transaction in the main
// chain.  In order to significantly optimize the space requirements a separate
// index which provides an internal mapping between each TokenID that has been
// indexed and a unique ID for use within the hash to location mappings.  The ID
// is simply a sequentially incremented uint32.  This is useful because it is
// only 4 bytes versus 32 bytes hashes and thus saves a ton of space in the
// index.
//
// There are three buckets used in total.  The first bucket maps the GroupID
// hash to the specific uint32 ID location.  The second bucket maps the
// uint32 of each GroupID to the actual GroupID hash and the third maps that
// unique transaction hash to unint32 GroupID and the tx's group value.
//
//
// The serialized format for keys and values in the TokenID hash to ID bucket is:
//   <group id hash> => <group id uint32>
//
//   Field           Type              Size
//   Group ID hash   []bytes     	   32 bytes (this is the sha256 hash of a whole group id, which includes subgroup component)
//   ID              uint32            4 bytes
//   -----
//   Total: 36 bytes
//
// The serialized format for keys and values in the ID to TokenID hash bucket is:
//   <group id uint32> => <parent id uint32><group or subgroup id bytes> <future group metadata>
//
//   Field            					Type              Size
//   ID               					uint32            4 bytes
//	 Parent Group ID					uint32			  4 bytes (this is zero'd out if not a subgroup)
//   Group ID                   		[]bytes   		  32 bytes normally, but this can be less if there is a parent group
//   (future) Genesis OP_RETURN         []bytes           varies, up to 223 bytes currently allowed in OP_RETURN space
//   -----
//   Max: X bytes max
//
// The serialized format for the keys and values in the slp index bucket is:
//
//   <txhash><vout> = <group id uint32><qty or flags>
//
//   Field           	Type              Size
//   <txhash><vout>     []bytes   	      36 bytes (32 byte hash + 4 byte uint32 vout)
//   group id        	uint32            4 bytes
//	 parent group id	uint32			  4 bytes (this is zero'd out if not a subgroup)
//	 quantity_or_flags	[]bytes			  2, 4, or 8 bytes
//   -----
//   Max: 16 bytes
//	 Min: 10 bytes
//
// -----------------------------------------------------------------------------

// GroupMetadata is used to hold the unmarshalled data parsed from
// the group id uint32 -> group id bytes index
type GroupMetadata struct {
	GroupIDBytes  []byte
	GroupID       uint32
	ParentGroupID uint32
}
type dbGroupMetadata struct {
	nonfinalGroupID []byte
	groupID         uint32
	parentGroupID   uint32
}

// dbPutGroupMetadataIndexEntry uses an existing database transaction to update or add
// the index entries for the hash to id and id to hash mappings for the provided
// values.
func dbPutGroupMetadataIndexEntry(dbTx database.Tx, groupID uint32, metadata *GroupMetadata) error {
	// Serialize the height for use in the index entries.
	var serializedID [4]byte
	byteOrder.PutUint32(serializedID[:], groupID)

	// Add the group id by group id hash mapping to the index.
	dbMeta := dbTx.Metadata()
	hashIndex := dbMeta.Bucket(groupIDByHashIndexBucketName)
	groupIDHash := sha256.Sum256(metadata.GroupIDBytes)
	if err := hashIndex.Put(groupIDHash[:], serializedID[:]); err != nil {
		return err
	}

	// Add or update token metadata by uint32 groupID mapping to the index.
	metadataIndex := dbMeta.Bucket(groupMetadataByIDIndexBucketName)
	serializedGroupMetadata := make([]byte, 4+len(metadata.GroupIDBytes))
	var parentGroupId [4]byte
	byteOrder.PutUint32(parentGroupId[:], metadata.ParentGroupID)
	copy(serializedGroupMetadata[0:], parentGroupId[:])
	if len(metadata.GroupIDBytes) > 32 {
		if metadata.ParentGroupID == 0 {
			return fmt.Errorf("cannot have a parent group id of 0 when group id is >32 bytes")
		}
		copy(serializedGroupMetadata[4:], metadata.GroupIDBytes[32:])
	} else {
		if metadata.ParentGroupID != 0 {
			return fmt.Errorf("parent group id must be 0 when group id is 32 bytes")
		}
		copy(serializedGroupMetadata[4:], metadata.GroupIDBytes)
	}
	return metadataIndex.Put(serializedID[:], serializedGroupMetadata)
}

// dbFetchGroupIDByHash uses an existing database transaction to retrieve the
// group id for the provided group id sha256 hash from the index.
func dbFetchGroupIDByHash(dbTx database.Tx, groupIDHash [32]byte) (uint32, error) {
	if len(groupIDHash) != 32 {
		return 0, fmt.Errorf("group id hash must have a length of 32 bytes")
	}
	hashIndex := dbTx.Metadata().Bucket(groupIDByHashIndexBucketName)
	serializedID := hashIndex.Get(groupIDHash[:])
	if serializedID == nil {
		return 0, errNoGroupIDHashEntry
	}
	return byteOrder.Uint32(serializedID), nil
}

// dbFetchGroupMetadataBySerializedID uses an existing database transaction to
// retrieve the hash for the provided serialized group id from the index.
func dbFetchGroupMetadataBySerializedID(dbTx database.Tx, serializedID []byte) (*dbGroupMetadata, error) {
	idIndex := dbTx.Metadata().Bucket(groupMetadataByIDIndexBucketName)
	serializedData := idIndex.Get(serializedID)
	if serializedData == nil {
		return nil, errNoGroupMetadataEntry
	}

	expectedMinSize := 4 + 32
	if len(serializedData) < expectedMinSize {
		return nil, fmt.Errorf("group metadata less than %s bytes %s", fmt.Sprint(expectedMinSize), hex.EncodeToString(serializedData))
	}

	// TODO: parse the group id into group flag and sub group id components ?

	tm := &dbGroupMetadata{
		nonfinalGroupID: serializedData[4:],
		parentGroupID:   byteOrder.Uint32(serializedData[:4]),
		groupID:         byteOrder.Uint32(serializedID),
	}
	return tm, nil
}

// dbFetchGroupMetadataByID uses an existing database transaction to retrieve the
// hash for the provided group id from the index.
func dbFetchGroupMetadataByID(dbTx database.Tx, id uint32) (*dbGroupMetadata, error) {
	var serializedID [4]byte
	byteOrder.PutUint32(serializedID[:], id)
	return dbFetchGroupMetadataBySerializedID(dbTx, serializedID[:])
}

type dbGroupIndexEntry struct {
	outpointID []byte
	groupID    []byte
	qtyOrFlags []byte
}

// dbPutGroupIndexEntry uses an existing database transaction to update the
// transaction index given the provided serialized data that is expected to have
// been serialized putGroupIndexEntry.
func dbPutGroupIndexEntry(idx *GroupIndex, dbTx database.Tx, entryInfo *dbGroupIndexEntry) error {
	//txHash := entryInfo.tx.TxHash()

	// get current tokenID uint32 for the tokenID hash, add new if needed
	groupID, err := dbFetchGroupIDByHash(dbTx, sha256.Sum256(entryInfo.groupID))
	if err != nil {
		groupID = idx.curTokenID + 1

		// 0 is used to indicate no parent group id
		var parentGroupID uint32
		parentGroupID = 0

		// check that we don't have a subgroup created before a parent group id
		// this could only happen if we don't topologically order the block transactions!
		if len(entryInfo.groupID) > 32 {
			parentGroupID, err = dbFetchGroupIDByHash(dbTx, sha256.Sum256(entryInfo.groupID[:32]))
			if err != nil {
				msg := fmt.Sprintf("parent group id not found for group %s (this should never happen)", hex.EncodeToString(entryInfo.groupID))
				log.Criticalf(msg)
				return errors.New(msg)
			}
		}

		err = dbPutGroupMetadataIndexEntry(dbTx, groupID,
			&GroupMetadata{
				GroupID:       groupID,
				GroupIDBytes:  entryInfo.groupID,
				ParentGroupID: parentGroupID,
			},
		)
		if err != nil {
			return fmt.Errorf("failed to update db for token id: %v, this should never happen", entryInfo.groupID)
		}
		log.Infof("new group %s %s, id: %s, parentid: %s", hex.EncodeToString(entryInfo.groupID), hex.EncodeToString(entryInfo.qtyOrFlags), fmt.Sprint(groupID), fmt.Sprint(parentGroupID))
		idx.curTokenID++
	}

	target := make([]byte, 4+len(entryInfo.qtyOrFlags))
	byteOrder.PutUint32(target[:], groupID)
	copy(target[4:], entryInfo.qtyOrFlags)
	groupIndex := dbTx.Metadata().Bucket(groupTxIndexKey)
	return groupIndex.Put(entryInfo.outpointID[:], target)
}

// GroupTxEntry is a valid slp token stored in the slp index
type GroupTxEntry struct {
	GroupID       uint32
	ParentGroupID uint32
	QtyOrFlags    []byte
	GroupIDBytes  []byte
}

// dbFetchGroupIndexEntry uses an existing database transaction to fetch the serialized slp
// index entry for the provided transaction hash.  When there is no entry for the provided hash,
// nil will be returned for the both the entry and the error.
func dbFetchGroupIndexEntry(dbTx database.Tx, outpointID []byte) (*GroupTxEntry, error) {
	// Load the record from the database and return now if it doesn't exist.
	GroupIndex := dbTx.Metadata().Bucket(groupTxIndexKey)
	serializedData := GroupIndex.Get(outpointID)
	if len(serializedData) == 0 {
		return nil, fmt.Errorf("slp entry does not exist %v", outpointID)
	}

	// Ensure the serialized data has enough bytes to properly deserialize.
	// The minimum possible entry size is 4 + 4 + 2 = 10
	if len(serializedData) < 10 {
		return nil, database.Error{
			ErrorCode: database.ErrCorruption,
			Description: fmt.Sprintf("corrupt slp index "+
				"entry for %s", outpointID),
		}
	}

	entry := &GroupTxEntry{
		GroupID:       byteOrder.Uint32(serializedData[0:4]),
		ParentGroupID: 0,
		QtyOrFlags:    serializedData[5:],
	}

	var groupIDBytes []byte

	// if parentID is > 0 this is a subgroup
	parentID := byteOrder.Uint32(serializedData[4:8])
	if parentID > 0 {
		parentGroupMetadata, err := dbFetchGroupMetadataByID(dbTx, parentID)
		if err != nil {
			return nil, err
		}
		entry.ParentGroupID = parentGroupMetadata.parentGroupID
		groupIDBytes = append(groupIDBytes, parentGroupMetadata.nonfinalGroupID...)
	}

	// get group id bytes for this group id
	groupMetadata, err := dbFetchGroupMetadataByID(dbTx, entry.GroupID)
	if err != nil {
		return nil, err
	}

	entry.GroupIDBytes = append(groupIDBytes, groupMetadata.nonfinalGroupID...)

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
		testGroupID := uint32(1)
		increment := uint32(1)
		for {
			md, err := dbFetchGroupMetadataByID(dbTx, testGroupID)
			if err != nil {
				if md != nil {
					return fmt.Errorf("could not init slp index: %v", err)
				}
				nextUnknown = testGroupID
				break
			}

			highestKnown = testGroupID
			testGroupID += increment
		}
		log.Tracef("Forward scan (highest known %d, next unknown %d)",
			highestKnown, nextUnknown)

		idx.curTokenID = highestKnown
		return nil
	})

	if err != nil {
		return err
	}

	log.Infof("Current number of group tokens in index: %v", idx.curTokenID)
	return nil
}

// StartBlock is used to indicate the proper start block for the index manager.
//
// This is part of the Indexer interface.
func (idx *GroupIndex) StartBlock() (*chainhash.Hash, int32) {
	return nil, -1
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
	if _, err := meta.CreateBucket(groupMetadataByIDIndexBucketName); err != nil {
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

	putTxIndexEntry := func(txHash *chainhash.Hash, vout uint32, groupIDBytes []byte, qtyOrFlags []byte) error {

		outpointID := make([]byte, 36)
		copy(outpointID[0:], txHash[:])
		voutSerialized := make([]byte, 4)
		byteOrder.PutUint32(voutSerialized, vout)
		copy(outpointID[32:], voutSerialized)

		log.Infof("group out %v:%s, %s %s", txHash, fmt.Sprint(vout), hex.EncodeToString(groupIDBytes), hex.EncodeToString(qtyOrFlags))

		return dbPutGroupIndexEntry(idx, dbTx, &dbGroupIndexEntry{
			outpointID: outpointID,
			groupID:    groupIDBytes,
			qtyOrFlags: qtyOrFlags,
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

// AddGroupTxIndexEntryHandler provides a function interface for CheckGroupTx
type AddGroupTxIndexEntryHandler func(*chainhash.Hash, uint32, []byte, []byte) error

// CheckGroupTx checks a transaction for validity and adds valid transactions to the db
//
// TODO: ? loop through inputs to delete them from the group index so that we only maintained
//       an unspent set of group related data ?
//
func CheckGroupTx(tx *wire.MsgTx, putTxIndexEntry AddGroupTxIndexEntryHandler) (bool, error) {

	txHash := tx.TxHash()
	hadOutput := false

	// look at the output scriptPubKey and parse out the group parts
	for vout, output := range tx.TxOut {

		// any OP_GROUP output will be larger than 35 bytes for sure
		// since the group id (min 32 bytes), the group value (min 2 bytes),
		// and the group opcode (1 byte) make up 35 bytes.  This doesn't
		// even account for the remaining part of the script.
		if len(output.PkScript) < 35 {
			continue
		}

		// parse the script into its data push components
		// and check that OP_GROUP is at index 2.
		disassembledScript, err := txscript.DisasmString(output.PkScript)
		if err != nil {
			log.Criticalf("group output script disasm failed: %v", err)
			continue
		}

		splitDisassembledScript := strings.Split(disassembledScript, " ")

		// use length check to filter out known non-group scripts since
		// group prefix has 3 items.
		if len(splitDisassembledScript) < 3 {
			continue
		}

		// group id is at index 0
		if len(splitDisassembledScript[0]) < 32*2 {
			log.Critical("OP_GROUP id is less than 32 bytes!")
			continue
		}
		groupID, err := hex.DecodeString(splitDisassembledScript[0])
		if err != nil {
			log.Criticalf("couldn't decode group id: %v", err)
			continue
		}

		// group value conforms to length requirement
		valLen := len(splitDisassembledScript[1])
		if valLen != 4 && valLen != 8 && valLen != 16 {
			log.Critical("OP_GROUP value is not 2, 4, or 8 bytes!")
			continue
		}
		groupVal, err := hex.DecodeString(splitDisassembledScript[1])
		if err != nil {
			log.Criticalf("couldn't decode group value: %v", err)
			continue
		}

		// group opcode is at index 3
		if splitDisassembledScript[2] != "OP_GROUP" {
			log.Critical("OP_GROUP not detected in output script!")
			continue
		}

		// save the group tx entry to the db
		err = putTxIndexEntry(&txHash, uint32(vout), groupID, groupVal)
		if err != nil {
			return false, err
		}

		hadOutput = true
	}

	return hadOutput, nil
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
func (idx *GroupIndex) GetGroupIndexEntry(dbTx database.Tx, hash []byte, vout uint32) (*GroupTxEntry, error) {
	// if entry, ok := idx.cache.GetGroupTxEntry(hash); ok {
	// 	log.Debugf("using slp txn entry cache for txid %v", hash)
	// 	return &entry, nil
	// }

	outpointID := make([]byte, 36)
	copy(outpointID, hash)
	byteOrder.PutUint32(outpointID[32:], vout)

	// fallback to fetch entry from db
	entry, err := dbFetchGroupIndexEntry(dbTx, outpointID)
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
//
// NOTE: currently since this group metadata
//
func (idx *GroupIndex) GetGroupMetadata(dbTx database.Tx, entry *GroupTxEntry) (*GroupMetadata, error) {
	// if tm, ok := idx.cache.GetGroupMetadata(&entry.TokenIDHash); ok {
	// 	log.Debugf("using token metadata cache for %s", hex.EncodeToString(entry.TokenIDHash[:]))
	// 	return &tm, nil
	// }

	groupIdBytes := make([]byte, 0)
	if entry.ParentGroupID > 0 {
		dbGroupMetadata, err := dbFetchGroupMetadataByID(dbTx, entry.ParentGroupID)
		if err != nil {
			return nil, err
		}
		groupIdBytes = append(groupIdBytes, dbGroupMetadata.nonfinalGroupID...)

		dbSubGroupMetadata, err := dbFetchGroupMetadataByID(dbTx, entry.GroupID)
		if err != nil {
			return nil, err
		}
		groupIdBytes = append(groupIdBytes, dbSubGroupMetadata.nonfinalGroupID...)
	} else {
		dbGroupMetadata, err := dbFetchGroupMetadataByID(dbTx, entry.GroupID)
		if err != nil {
			return nil, err
		}
		copy(groupIdBytes, dbGroupMetadata.nonfinalGroupID)
	}

	if len(groupIdBytes) < 32 {
		return nil, fmt.Errorf("group id cannot be smaller than 32 bytes")
	}

	tm := &GroupMetadata{
		GroupIDBytes:  groupIdBytes,
		ParentGroupID: entry.ParentGroupID,
		GroupID:       entry.GroupID,
	}

	// err = idx.cache.AddTempGroupMetadata(*tm)
	// if err != nil {
	// 	log.Criticalf("AddTempGroupMetadata in GetGroupMetadata failed: ", err)
	// }

	return tm, nil
}

// AddPotentialSlpEntries checks if a transaction is slp valid and then will add a
// new GroupIndexEntry to the shared cache of valid slp transactions.
// func (idx *GroupIndex) AddPotentialSlpEntries(dbTx database.Tx, msgTx *wire.MsgTx) (bool, error) {
//
// TODO: this is used for mempool handling
//
// }

// RemoveMempoolSlpTxs removes a list of transactions from the temporary cache that holds
// both mempool and recently queried GroupIndexEntries
func (idx *GroupIndex) RemoveMempoolSlpTxs(txs []*bchutil.Tx) {
	idx.cache.RemoveMempoolSlpTxItems(txs)
}

// GroupConfig provides the proper starting height and hash
type GroupConfig struct {
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

		return meta.DeleteBucket(groupMetadataByIDIndexBucketName)
	})
}

// DropGroupIndex drops the transaction index from the provided database if it
// exists.  Since the address index relies on it, the address index will also be
// dropped when it exists.
func DropGroupIndex(db database.DB, interrupt <-chan struct{}) error {
	return dropIndex(db, groupTxIndexKey, groupTokenIndexName, interrupt)
}
