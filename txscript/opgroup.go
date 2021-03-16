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

// Flag holds the value/string representation for an authority or group flag
type Flag struct {
	value int
	name  string
}

const (
	// TokenTypeOpGroup version type used for ParseResult.TokenType
	TokenTypeOpGroup TokenType = 10

	// IsAuthorityFlag flag is used to control whether
	// or not the value associated with the OP_GROUP
	// value in scriptPubKey is a token quantity or
	// authority flag(s)
	//
	// From the spec:
	// This is an authority UTXO, not a “normal”
	// quantity holding UTXO
	//
	IsAuthorityFlag = 1 << 63

	// GroupIsBchStr ...
	GroupIsBchStr = "HoldsBch"

	// GroupIsBchFlag ...
	GroupIsBchFlag = 2

	// ReservedGroupFlags ...
	ReservedGroupFlags = 0xfffd
)

var (
	// MintAuthorityFlag
	MintAuthorityFlag = Flag{
		value: 1 << 62,
		name:  "MintAuthority",
	}

	// MeltAuthorityFlag
	MeltAuthorityFlag = Flag{
		value: 1 << 61,
		name:  "MeltAuthority",
	}

	// BatonAuthorityFlag
	BatonAuthorityFlag = Flag{
		value: 1 << 60,
		name:  "BatonAuthority",
	}

	// RescriptAuthorityFlag
	RescriptAuthorityFlag = Flag{
		value: 1 << 59,
		name:  "RescriptAuthority",
	}

	// SubgroupAuthorityFlag
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

	// GroupCovenant
	GroupCovenantFlag = Flag{
		value: 1,
		name:  "Covenant",
	}

	// GroupHoldsBch
	GroupHoldsBchFlag = Flag{
		value: 2,
		name:  "HoldsBch",
	}
)

// GroupOutput is an unmarshalled OP_GROUP ParseResult
type GroupOutput struct {
	groupID         []byte
	quantityOrFlags uint64
	groupFlags      uint16
}

// TokenType returns the TokenType per the ParserResult interface
func (r GroupOutput) TokenType() TokenType {
	return TokenTypeOpGroup
}

// TokenID returns the TokenID per the ParserResult interface
func (r GroupOutput) TokenID() []byte {
	return r.groupID
}

// IsAuthority returns a boolean indicating whether or not this
// group output is an authority output
func (r GroupOutput) IsAuthority() bool {
	return r.quantityOrFlags&uint64(IsAuthorityFlag) == 1
}

// Amount of the output
func (r GroupOutput) Amount() (*uint64, error) {
	return nil, errors.New("unimplemented")
}

// IsMintAuthority ...
func (r GroupOutput) IsMintAuthority() (bool, error) {
	if !r.IsAuthority() {
		return false, errors.New("not an authority output")
	}
	return r.quantityOrFlags&uint64(MintAuthorityFlag.value) == 1, nil
}

// IsMeltAuthority ...
func (r GroupOutput) IsMeltAuthority() (bool, error) {
	if !r.IsAuthority() {
		return false, errors.New("not an authority output")
	}
	return r.quantityOrFlags&uint64(MeltAuthorityFlag.value) == 1, nil
}

// IsSubGroupAuthority ...
func (r GroupOutput) IsSubGroupAuthority() (bool, error) {
	if !r.IsAuthority() {
		return false, errors.New("not an authority output")
	}
	return r.quantityOrFlags&uint64(SubgroupAuthorityFlag.value) == 1, nil
}

// IsRescriptAuthority ...
func (r GroupOutput) IsRescriptAuthority() (bool, error) {
	if !r.IsAuthority() {
		return false, errors.New("not an authority output")
	}
	return r.quantityOrFlags&uint64(RescriptAuthorityFlag.value) == 1, nil
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
	if hasFlag, _ := r.IsMintAuthority(); hasFlag {
		flags = append(flags, MintAuthorityFlag)
	}

	// check Melt authority
	if hasFlag, _ := r.IsMeltAuthority(); hasFlag {
		flags = append(flags, MeltAuthorityFlag)
	}

	// check Subgroup authority
	if hasFlag, _ := r.IsSubGroupAuthority(); hasFlag {
		flags = append(flags, SubgroupAuthorityFlag)
	}

	// check Rescript authority
	if hasFlag, _ := r.IsRescriptAuthority(); hasFlag {
		// TODO: check group flags for covenant flag
		flags = append(flags, RescriptAuthorityFlag)
	}

	if len(flags) == 0 {
		return nil, errors.New("authority output has no flags set")
	}

	return flags, nil
}

// IsGroupBch ...
func (r GroupOutput) IsGroupBch() bool {
	return r.groupFlags&GroupIsBchFlag == 1
}

// IsGroupCovenant ...
func (r GroupOutput) IsGroupCovenant() bool {
	return r.groupFlags&uint16(GroupCovenantFlag.value) == 1
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

// ParseOpGroupScript
func ParseOpGroupOutput(scriptPubKey []byte) (*GroupOutput, error) {
	groupOutput := &GroupOutput{}

	// parse the script into its data push components
	// and check that OP_GROUP is at index 2.
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

	// group id is at index 0
	if len(splitDisassembledScript[0]) < 32*2 {
		return nil, fmt.Errorf("OP_GROUP id is less than 32 bytes!")
	}
	groupID, err := hex.DecodeString(splitDisassembledScript[0])
	if err != nil {
		return nil, fmt.Errorf("couldn't decode group id: %v", err)
	}
	groupOutput.groupID = groupID
	groupOutput.groupFlags = binary.LittleEndian.Uint16(groupID[31:33])

	// group value conforms to length requirement
	valLen := len(splitDisassembledScript[1])
	if valLen != 4 && valLen != 8 && valLen != 16 {
		return nil, fmt.Errorf("OP_GROUP value is not 2, 4, or 8 bytes!")
	}

	groupVal, err := hex.DecodeString(splitDisassembledScript[1])
	if err != nil {
		return nil, fmt.Errorf("couldn't decode group value: %v", err)
	}
	groupOutput.quantityOrFlags = binary.LittleEndian.Uint64(groupVal)

	// group opcode is at index 3
	if splitDisassembledScript[2] != "OP_GROUP" {
		return nil, fmt.Errorf("OP_GROUP not detected in output script!")
	}

	return groupOutput, nil
}
