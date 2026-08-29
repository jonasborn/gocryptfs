// Package blobmeta implements the FS v3 per-file info-chunk (CON-3.1): the
// encrypted metadata record that is a prefix of every file's backing blob.
//
// It deliberately has no dependency on the card, the keyserver, FUSE, or any
// gocryptfs internal/ package (so it can be imported from the 115fs CLI as
// well). Callers pass in the 32-byte AES-256-GCM key for a given file
// (K_meta, card-derived per CON-3.1) and get framed, sealed 512-byte units
// back, or parse them the other way.
package blobmeta

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

// SchemaVersion is the MetaRecord schema version carried in tag tagSchemaVersion.
const SchemaVersion uint16 = 1

// NameMax is the maximum length of a single path component, in bytes.
const NameMax = 255

// SymlinkTargetMax bounds a symlink target, matching the usual PATH_MAX.
const SymlinkTargetMax = 4096

// maxRecordLen is the hard ceiling on a marshaled record: the info-chunk
// frames its total length in a uint16 (see chunk.go).
const maxRecordLen = 0xFFFF

// FileType classifies a blob.
type FileType uint8

const (
	TypeRegular FileType = 1
	TypeDir     FileType = 2
	TypeSymlink FileType = 3
)

func (t FileType) valid() bool {
	return t == TypeRegular || t == TypeDir || t == TypeSymlink
}

// TLV tags. Unknown tags are rejected on decode (no backward compat to keep).
const (
	tagSchemaVersion = 0x01
	tagFileUUID      = 0x02
	tagParentDirID   = 0x03
	tagName          = 0x04
	tagType          = 0x05
	tagMode          = 0x06
	tagUID           = 0x07
	tagGID           = 0x08
	tagAtime         = 0x09
	tagMtime         = 0x0A
	tagCtime         = 0x0B
	tagBtime         = 0x0C
	tagSize          = 0x0D
	tagSymlinkTarget = 0x0E
	tagXattr         = 0x0F
)

// Xattr is a single extended attribute.
type Xattr struct {
	Name  string
	Value []byte
}

// MetaRecord is the decoded per-file metadata. Timestamps are unix
// nanoseconds; Btime == 0 means "unknown".
type MetaRecord struct {
	SchemaVersion uint16
	FileUUID      [16]byte
	ParentDirID   [16]byte
	Name          string
	Type          FileType
	Mode          uint32
	UID           uint32
	GID           uint32
	Atime         int64
	Mtime         int64
	Ctime         int64
	Btime         int64
	Size          int64
	SymlinkTarget string
	Xattrs        []Xattr
}

// IsRoot reports whether this record is the filesystem root directory blob.
func (r *MetaRecord) IsRoot() bool {
	return r.Type == TypeDir && r.FileUUID == RootDirUUID && r.ParentDirID == ([16]byte{})
}

var (
	errNameInvalid   = errors.New("blobmeta: name is empty, too long, or contains '/' or NUL")
	errTypeInvalid   = errors.New("blobmeta: invalid file type")
	errRecordTooBig  = errors.New("blobmeta: marshaled record exceeds 65535 bytes")
	errTruncated     = errors.New("blobmeta: TLV record is truncated")
	errUnknownTag    = errors.New("blobmeta: unknown TLV tag")
	errDuplicateTag  = errors.New("blobmeta: duplicate TLV tag")
	errMissingField  = errors.New("blobmeta: required field missing")
	errSymlinkTarget = errors.New("blobmeta: symlink target set on non-symlink, or empty/too long on symlink")
)

// validateName enforces the single-component name rules. The root directory
// blob is the one record allowed an empty name.
func validateName(name string, isRoot bool) error {
	if name == "" {
		if isRoot {
			return nil
		}
		return errNameInvalid
	}
	if len(name) > NameMax || !utf8.ValidString(name) {
		return errNameInvalid
	}
	if strings.ContainsRune(name, '/') || strings.IndexByte(name, 0) >= 0 {
		return errNameInvalid
	}
	if name == "." || name == ".." {
		return errNameInvalid
	}
	return nil
}

// Validate checks a record for internal consistency before it is marshaled
// or after it is decoded.
func (r *MetaRecord) Validate() error {
	if !r.Type.valid() {
		return errTypeInvalid
	}
	if err := validateName(r.Name, r.IsRoot()); err != nil {
		return err
	}
	if r.Type == TypeSymlink {
		if r.SymlinkTarget == "" || len(r.SymlinkTarget) > SymlinkTargetMax || !utf8.ValidString(r.SymlinkTarget) {
			return errSymlinkTarget
		}
	} else if r.SymlinkTarget != "" {
		return errSymlinkTarget
	}
	for _, x := range r.Xattrs {
		// The encoded entry is 2 (nameLen) + name + value and rides in a
		// TLV value that is itself uint16-framed.
		if x.Name == "" || 2+len(x.Name)+len(x.Value) > 0xFFFF {
			return fmt.Errorf("blobmeta: invalid or oversized xattr %q", x.Name)
		}
	}
	return nil
}

// appendTLV writes one [tag][uint16 len][value] entry.
func appendTLV(dst []byte, tag byte, value []byte) []byte {
	if len(value) > 0xFFFF {
		// Callers never pass anything this large for the fixed-width tags;
		// the xattr path checks length in Validate first.
		panic("blobmeta: TLV value too long")
	}
	var hdr [3]byte
	hdr[0] = tag
	binary.BigEndian.PutUint16(hdr[1:], uint16(len(value)))
	dst = append(dst, hdr[:]...)
	return append(dst, value...)
}

func appendU16(dst []byte, tag byte, v uint16) []byte {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], v)
	return appendTLV(dst, tag, b[:])
}

func appendU32(dst []byte, tag byte, v uint32) []byte {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return appendTLV(dst, tag, b[:])
}

func appendI64(dst []byte, tag byte, v int64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(v))
	return appendTLV(dst, tag, b[:])
}

// Marshal serializes the record to its TLV form in a fixed, deterministic
// field order. It returns errRecordTooBig if the result would not fit the
// info-chunk's uint16 length frame.
func (r *MetaRecord) Marshal() ([]byte, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	sv := r.SchemaVersion
	if sv == 0 {
		sv = SchemaVersion
	}

	buf := make([]byte, 0, 256)
	buf = appendU16(buf, tagSchemaVersion, sv)
	buf = appendTLV(buf, tagFileUUID, r.FileUUID[:])
	buf = appendTLV(buf, tagParentDirID, r.ParentDirID[:])
	buf = appendTLV(buf, tagName, []byte(r.Name))
	buf = appendTLV(buf, tagType, []byte{byte(r.Type)})
	buf = appendU32(buf, tagMode, r.Mode)
	buf = appendU32(buf, tagUID, r.UID)
	buf = appendU32(buf, tagGID, r.GID)
	buf = appendI64(buf, tagAtime, r.Atime)
	buf = appendI64(buf, tagMtime, r.Mtime)
	buf = appendI64(buf, tagCtime, r.Ctime)
	buf = appendI64(buf, tagBtime, r.Btime)
	buf = appendI64(buf, tagSize, r.Size)
	if r.Type == TypeSymlink {
		buf = appendTLV(buf, tagSymlinkTarget, []byte(r.SymlinkTarget))
	}
	for _, x := range r.Xattrs {
		v := make([]byte, 0, 2+len(x.Name)+len(x.Value))
		var nl [2]byte
		binary.BigEndian.PutUint16(nl[:], uint16(len(x.Name)))
		v = append(v, nl[:]...)
		v = append(v, x.Name...)
		v = append(v, x.Value...)
		buf = appendTLV(buf, tagXattr, v)
	}

	if len(buf) > maxRecordLen {
		return nil, errRecordTooBig
	}
	return buf, nil
}

// seen tracks which non-repeatable tags have already been consumed.
type seen map[byte]bool

// UnmarshalRecord parses a TLV record. Unknown tags, duplicate
// non-repeatable tags, truncation, and missing required fields are all
// errors.
func UnmarshalRecord(buf []byte) (*MetaRecord, error) {
	var r MetaRecord
	got := seen{}
	i := 0
	for i < len(buf) {
		if i+3 > len(buf) {
			return nil, errTruncated
		}
		tag := buf[i]
		l := int(binary.BigEndian.Uint16(buf[i+1 : i+3]))
		i += 3
		if i+l > len(buf) {
			return nil, errTruncated
		}
		val := buf[i : i+l]
		i += l

		if tag != tagXattr {
			if got[tag] {
				return nil, fmt.Errorf("%w: 0x%02x", errDuplicateTag, tag)
			}
			got[tag] = true
		}

		switch tag {
		case tagSchemaVersion:
			if l != 2 {
				return nil, errTruncated
			}
			r.SchemaVersion = binary.BigEndian.Uint16(val)
		case tagFileUUID:
			if l != 16 {
				return nil, errTruncated
			}
			copy(r.FileUUID[:], val)
		case tagParentDirID:
			if l != 16 {
				return nil, errTruncated
			}
			copy(r.ParentDirID[:], val)
		case tagName:
			r.Name = string(val)
		case tagType:
			if l != 1 {
				return nil, errTruncated
			}
			r.Type = FileType(val[0])
		case tagMode:
			if l != 4 {
				return nil, errTruncated
			}
			r.Mode = binary.BigEndian.Uint32(val)
		case tagUID:
			if l != 4 {
				return nil, errTruncated
			}
			r.UID = binary.BigEndian.Uint32(val)
		case tagGID:
			if l != 4 {
				return nil, errTruncated
			}
			r.GID = binary.BigEndian.Uint32(val)
		case tagAtime:
			r.Atime = readI64(val)
		case tagMtime:
			r.Mtime = readI64(val)
		case tagCtime:
			r.Ctime = readI64(val)
		case tagBtime:
			r.Btime = readI64(val)
		case tagSize:
			r.Size = readI64(val)
		case tagSymlinkTarget:
			r.SymlinkTarget = string(val)
		case tagXattr:
			x, err := parseXattr(val)
			if err != nil {
				return nil, err
			}
			r.Xattrs = append(r.Xattrs, x)
		default:
			return nil, fmt.Errorf("%w: 0x%02x", errUnknownTag, tag)
		}
	}

	for _, req := range []byte{tagFileUUID, tagParentDirID, tagName, tagType} {
		if !got[req] {
			return nil, fmt.Errorf("%w: 0x%02x", errMissingField, req)
		}
	}
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return &r, nil
}

func readI64(b []byte) int64 {
	if len(b) != 8 {
		return 0
	}
	return int64(binary.BigEndian.Uint64(b))
}

func parseXattr(val []byte) (Xattr, error) {
	if len(val) < 2 {
		return Xattr{}, errTruncated
	}
	nl := int(binary.BigEndian.Uint16(val[:2]))
	if 2+nl > len(val) {
		return Xattr{}, errTruncated
	}
	return Xattr{
		Name:  string(val[2 : 2+nl]),
		Value: append([]byte(nil), val[2+nl:]...),
	}, nil
}
