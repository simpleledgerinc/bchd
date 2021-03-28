package txscript

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// TokenType is an uint16 representing the slp version type
type TokenType uint16

const (
	// TokenTypeOpGroup version type used for group outputs with no slp v2 association
	TokenTypeOpGroup TokenType = 0

	// TokenTypeOpGroup version type used for group outputs with slp v2 genesis metadata
	TokenTypeOpGroupSlpV2 TokenType = 2

	// TokenTypeOpGroup version type used for group outputs with slp v2 nft genesis metadata & is a valid nft
	TokenTypeOpGroupSlpV2Nft TokenType = 66

	// IsAuthorityFlag flag is used to control whether
	// or not the value associated with the op_group
	// value in scriptPubKey is a token quantity or
	// authority flag(s)
	//
	// From the spec:
	// This is an authority utxo, not a “normal”
	// quantity holding utxo
	//
	IsAuthorityFlag = 1 << 63

	// GroupIsBchStr ...
	GroupIsBchStr = "HoldsBch"

	// GroupIsBchFlag ...
	GroupIsBchFlag = 2

	// ReservedGroupFlags ...
	ReservedGroupFlags = 0xfffd
)

// Flag holds the value/string representation for an authority or group flag
type Flag struct {
	value int
	name  string
}

var (
	// MintAuthorityFlag ...
	MintAuthorityFlag = Flag{
		value: 1 << 62,
		name:  "MintAuthority",
	}

	// MeltAuthorityFlag ...
	MeltAuthorityFlag = Flag{
		value: 1 << 61,
		name:  "MeltAuthority",
	}

	// BatonAuthorityFlag ...
	BatonAuthorityFlag = Flag{
		value: 1 << 60,
		name:  "BatonAuthority",
	}

	// RescriptAuthorityFlag ...
	RescriptAuthorityFlag = Flag{
		value: 1 << 59,
		name:  "RescriptAuthority",
	}

	// SubgroupAuthorityFlag ...
	SubgroupAuthorityFlag = Flag{
		value: 1 << 58,
		name:  "SubgroupAuthority",
	}

	// ActiveAuthorityFlags ...
	ActiveAuthorityFlags = uint64(MintAuthorityFlag.value |
		MeltAuthorityFlag.value |
		BatonAuthorityFlag.value |
		RescriptAuthorityFlag.value |
		SubgroupAuthorityFlag.value)

	// AllAuthorityFlags ...
	AllAuthorityFlags = uint64(0xffff) << (64 - 16)

	// ReservedAuthorityFlags ...
	ReservedAuthorityFlags = AllAuthorityFlags ^ uint64(ActiveAuthorityFlags)

	// GroupCovenant ...
	GroupCovenantFlag = Flag{
		value: 1,
		name:  "Covenant",
	}

	// GroupHoldsBch ...
	GroupHoldsBchFlag = Flag{
		value: 2,
		name:  "HoldsBch",
	}
)

// GroupOutput is an unmarshalled op_group ParseResult
type GroupOutput struct {
	tokenType       TokenType
	groupID         []byte
	quantityOrFlags uint64
	groupFlags      uint16
}

// TokenType returns the TokenType per the ParserResult interface
func (r GroupOutput) TokenType() TokenType {
	return r.tokenType
}

// TokenID returns the TokenID per the ParserResult interface
func (r GroupOutput) TokenID() []byte {
	return r.groupID
}

// IsAuthority returns a boolean indicating whether or not this
// group output is an authority output
func (r GroupOutput) IsAuthority() bool {
	log.Infof("IsAuthority - %s", fmt.Sprint(r.quantityOrFlags))
	return r.quantityOrFlags&uint64(IsAuthorityFlag) > 0
}

// Amount of the output
func (r GroupOutput) Amount() uint64 {
	if r.IsAuthority() {
		return 0
	}
	return r.quantityOrFlags
}

// IsMintAuthority ...
func (r GroupOutput) IsMintAuthority() bool {
	return r.quantityOrFlags&uint64(MintAuthorityFlag.value) > 0
}

// IsMeltAuthority ...
func (r GroupOutput) IsMeltAuthority() bool {
	return r.quantityOrFlags&uint64(MeltAuthorityFlag.value) > 0
}

// IsSubGroupAuthority ...
func (r GroupOutput) IsSubGroupAuthority() bool {
	return r.quantityOrFlags&uint64(SubgroupAuthorityFlag.value) > 0
}

// IsRescriptAuthority ...
func (r GroupOutput) IsRescriptAuthority() bool {
	return r.quantityOrFlags&uint64(RescriptAuthorityFlag.value) > 0
}

// AuthorityFlags returns authority flags associated with this output. An error
// is returned if this is an amount output.
func (r GroupOutput) AuthorityFlags() ([]Flag, error) {
	flags := []Flag{}
	if !r.IsAuthority() {
		return nil, errors.New("output is not an authority")
	}

	// check unsupported flags
	if r.quantityOrFlags&ReservedAuthorityFlags > 0 {
		return nil, errors.New("authority output contains un-supported flags")
	}

	// check Mint authority
	if r.IsMintAuthority() {
		flags = append(flags, MintAuthorityFlag)
	}

	// check Melt authority
	if r.IsMeltAuthority() {
		flags = append(flags, MeltAuthorityFlag)
	}

	// check Subgroup authority
	if r.IsSubGroupAuthority() {
		flags = append(flags, SubgroupAuthorityFlag)
	}

	// check Rescript authority
	if r.IsRescriptAuthority() {
		// TODO: sanity check group flags for covenant flag?
		flags = append(flags, RescriptAuthorityFlag)
	}

	if len(flags) == 0 {
		return nil, errors.New("authority output has no flags set")
	}

	return flags, nil
}

// IsGroupBch ...
func (r GroupOutput) IsGroupBch() bool {
	return r.groupFlags&GroupIsBchFlag > 0
}

// IsGroupCovenant ...
func (r GroupOutput) IsGroupCovenant() bool {
	return r.groupFlags&uint16(GroupCovenantFlag.value) > 0
}

// GroupFlags returns group flags associated with the token id involved in
// this output.
func (r GroupOutput) GroupFlags() ([]Flag, error) {
	flags := []Flag{}

	if r.groupFlags&ReservedGroupFlags > 0 {
		return nil, errors.New("group token id contains un-supported flags")
	}

	if r.IsGroupBch() {
		flags = append(flags, GroupHoldsBchFlag)
	}

	if r.IsGroupCovenant() {
		flags = append(flags, GroupCovenantFlag)
	}

	return flags, nil
}

// MarshalGroupOutput ...
func MarshalGroupOutput(groupID []byte, groupVal []byte) (*GroupOutput, error) {
	if len(groupID) < 32 {
		return nil, fmt.Errorf("invalid group id %s", hex.EncodeToString(groupID))
	}

	groupOutput := &GroupOutput{
		groupID:    groupID,
		groupFlags: binary.LittleEndian.Uint16(groupID[30:32]),
	}

	valLen := len(groupVal)
	switch valLen {
	case 2:
		groupOutput.quantityOrFlags = uint64(binary.LittleEndian.Uint16(groupVal))
		break
	case 4:
		groupOutput.quantityOrFlags = uint64(binary.LittleEndian.Uint32(groupVal))
		break
	case 8:
		groupOutput.quantityOrFlags = uint64(binary.LittleEndian.Uint64(groupVal))
		break
	default:
		return nil, fmt.Errorf("group value is not 2, 4, or 8 bytes, got %s", hex.EncodeToString(groupVal))
	}

	return groupOutput, nil
}

// ParseGroupOutputScript ...
func ParseGroupOutputScript(scriptPubKey []byte) (*GroupOutput, error) {

	// parse the script into its data push components
	// and check that op_group is at index 2.
	disassembledScript, err := DisasmString(scriptPubKey)
	if err != nil {
		return nil, fmt.Errorf("group output script disasm failed: %v", err)
	}
	splitDisassembledScript := strings.Split(disassembledScript, " ")

	// use length check to filter out known non-group scripts since
	// group prefix has 3 items.
	if len(splitDisassembledScript) < 3 {
		return nil, fmt.Errorf("script is not long enough")
	}

	// group opcode is at index 3
	if splitDisassembledScript[2] != "OP_GROUP" {
		return nil, fmt.Errorf("group opcode not detected in output script!")
	}

	// group id is at index 0
	groupID, err := hex.DecodeString(splitDisassembledScript[0])
	if err != nil {
		return nil, fmt.Errorf("couldn't decode group id: %v", err)
	}

	if len(groupID) < 32 {
		return nil, fmt.Errorf("group opcode id is less than 32 bytes")
	}

	groupVal, err := hex.DecodeString(splitDisassembledScript[1])
	if err != nil {
		return nil, fmt.Errorf("couldn't decode group value: %v", err)
	}

	log.Infof("groupVal %s", splitDisassembledScript[1])

	return MarshalGroupOutput(groupID, groupVal)
}
