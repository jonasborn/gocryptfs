package blobmeta

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
)

func sampleRecord() *MetaRecord {
	return &MetaRecord{
		SchemaVersion: SchemaVersion,
		FileUUID:      [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		ParentDirID:   [16]byte{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1},
		Name:          "notes.txt",
		Type:          TypeRegular,
		Mode:          0o644,
		UID:           1000,
		GID:           1000,
		Atime:         1_700_000_000_000_000_001,
		Mtime:         1_700_000_000_000_000_002,
		Ctime:         1_700_000_000_000_000_003,
		Btime:         1_700_000_000_000_000_004,
		Size:          4001,
	}
}

func TestRecordRoundTrip(t *testing.T) {
	in := sampleRecord()
	buf, err := in.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	out, err := UnmarshalRecord(buf)
	if err != nil {
		t.Fatalf("UnmarshalRecord: %v", err)
	}
	if !reflect.DeepEqual(out, in) {
		t.Fatalf("round trip mismatch:\n in=%+v\nout=%+v", in, out)
	}
}

func TestRecordRoundTripSymlinkAndXattrs(t *testing.T) {
	in := sampleRecord()
	in.Type = TypeSymlink
	in.Name = "link"
	in.SymlinkTarget = "../deep/target/path"
	in.Xattrs = []Xattr{
		{Name: "user.comment", Value: []byte("hello world")},
		{Name: "security.selinux", Value: bytes.Repeat([]byte{0xAB}, 300)},
	}
	buf, err := in.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	out, err := UnmarshalRecord(buf)
	if err != nil {
		t.Fatalf("UnmarshalRecord: %v", err)
	}
	if out.SymlinkTarget != in.SymlinkTarget {
		t.Fatalf("symlink target: got %q want %q", out.SymlinkTarget, in.SymlinkTarget)
	}
	if len(out.Xattrs) != 2 || out.Xattrs[0].Name != "user.comment" ||
		!bytes.Equal(out.Xattrs[1].Value, in.Xattrs[1].Value) {
		t.Fatalf("xattrs round trip mismatch: %+v", out.Xattrs)
	}
}

func TestRootRecord(t *testing.T) {
	r := &MetaRecord{
		FileUUID: RootDirUUID,
		Name:     "",
		Type:     TypeDir,
	}
	if !r.IsRoot() {
		t.Fatal("expected IsRoot() true")
	}
	buf, err := r.Marshal()
	if err != nil {
		t.Fatalf("Marshal root: %v", err)
	}
	if _, err := UnmarshalRecord(buf); err != nil {
		t.Fatalf("UnmarshalRecord root: %v", err)
	}
}

func TestNameValidation(t *testing.T) {
	for _, bad := range []string{"", "a/b", "with\x00nul", ".", "..", strings.Repeat("x", NameMax+1)} {
		r := sampleRecord()
		r.Name = bad
		if _, err := r.Marshal(); err == nil {
			t.Fatalf("expected Marshal to reject name %q", bad)
		}
	}
	r := sampleRecord()
	r.Name = strings.Repeat("x", NameMax)
	if _, err := r.Marshal(); err != nil {
		t.Fatalf("255-byte name should be accepted: %v", err)
	}
}

func TestTypeValidation(t *testing.T) {
	r := sampleRecord()
	r.Type = 0
	if _, err := r.Marshal(); err == nil {
		t.Fatal("expected Marshal to reject type 0")
	}
	r.Type = 99
	if _, err := r.Marshal(); err == nil {
		t.Fatal("expected Marshal to reject type 99")
	}
}

func TestSymlinkTargetValidation(t *testing.T) {
	r := sampleRecord() // regular file
	r.SymlinkTarget = "/etc/passwd"
	if _, err := r.Marshal(); err == nil {
		t.Fatal("expected rejection: symlink target on regular file")
	}

	r = sampleRecord()
	r.Type = TypeSymlink
	r.SymlinkTarget = ""
	if _, err := r.Marshal(); err == nil {
		t.Fatal("expected rejection: empty symlink target")
	}
}

func TestUnknownTagRejected(t *testing.T) {
	buf, _ := sampleRecord().Marshal()
	// Append a well-formed but unknown TLV entry (tag 0x7F, len 0).
	buf = append(buf, 0x7F, 0x00, 0x00)
	if _, err := UnmarshalRecord(buf); err == nil {
		t.Fatal("expected UnmarshalRecord to reject unknown tag")
	}
}

func TestDuplicateTagRejected(t *testing.T) {
	buf, _ := sampleRecord().Marshal()
	buf = appendU32(buf, tagMode, 0o600) // second Mode entry
	if _, err := UnmarshalRecord(buf); err == nil {
		t.Fatal("expected UnmarshalRecord to reject duplicate tag")
	}
}

func TestTruncatedRejected(t *testing.T) {
	buf, _ := sampleRecord().Marshal()
	if _, err := UnmarshalRecord(buf[:len(buf)-3]); err == nil {
		t.Fatal("expected UnmarshalRecord to reject truncated buffer")
	}
	// Header claims more bytes than are present.
	bad := []byte{tagName, 0xFF, 0xFF, 'a', 'b'}
	if _, err := UnmarshalRecord(bad); err == nil {
		t.Fatal("expected UnmarshalRecord to reject over-long TLV length")
	}
}

func TestMissingRequiredFieldRejected(t *testing.T) {
	// Only a schema-version entry: no uuid/parent/name/type.
	buf := appendU16(nil, tagSchemaVersion, SchemaVersion)
	if _, err := UnmarshalRecord(buf); err == nil {
		t.Fatal("expected UnmarshalRecord to reject record missing required fields")
	}
}

func TestOversizedXattrRejected(t *testing.T) {
	r := sampleRecord()
	// A single xattr whose encoded form does not fit its own uint16 frame.
	r.Xattrs = []Xattr{{Name: "user.big", Value: bytes.Repeat([]byte{0}, 0xFFFF)}}
	if _, err := r.Marshal(); err == nil {
		t.Fatal("expected Marshal to reject oversized xattr")
	}
}

func TestRecordTooBig(t *testing.T) {
	r := sampleRecord()
	// Many individually-valid xattrs that together exceed the record's
	// uint16 length frame.
	for i := 0; i < 40; i++ {
		r.Xattrs = append(r.Xattrs, Xattr{
			Name:  "user.pad" + string(rune('A'+i)),
			Value: bytes.Repeat([]byte{byte(i)}, 4000),
		})
	}
	if _, err := r.Marshal(); err == nil {
		t.Fatal("expected Marshal to reject record past 65535 bytes")
	}
}
