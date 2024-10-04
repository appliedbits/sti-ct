package types

import (
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/certificate-transparency-go/tls"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/certificate-transparency-go/x509util"
	"github.com/google/trillian"
)

type Config struct {
	TrustedRootsPath     string
	LogConnectionTimeout time.Duration
	TLogEndpoint         string
	TLogAdminEndpoint	 string
	TLogID               int64
	KeysPath             string
}

type LogInfo struct {
	LogClient     trillian.TrillianLogClient
	Signer        crypto.Signer
	TrustedRoots  *x509util.PEMCertPool
	TLogID 	      int64
}

type AddChainRequest struct {
	Chain [][]byte `json:"chain"`
}

type PreCert struct {
	IssuerKeyHash  [sha256.Size]byte	`json:"issuer_key_hash"`
	TBSCertificate []byte				`json:"tbs_certificate"`
}

type ASN1Cert struct {
	Data []byte `json:"data"`
}

type JSONDataEntry struct {
	Data []byte `json:"data"`
}

type CTExtensions []byte

type Version uint64

const (
	V1 Version = 0
)

type MerkleLeafType uint64

const TimestampedEntryLeafType MerkleLeafType = 0

func (m MerkleLeafType) String() string {
	switch m {
	case TimestampedEntryLeafType:
		return "TimestampedEntryLeafType"
	default:
		return fmt.Sprintf("UnknownLeafType(%d)", m)
	}
}

type TimestampedEntry struct {
	Timestamp    uint64				`json:"timestamp"`
	EntryType    LogEntryType		`json:"entry_type"`
	X509Entry    *ASN1Cert			`json:"x509_entry"`
	PrecertEntry *PreCert			`json:"precert_entry"`
	JSONEntry    *JSONDataEntry		`json:"json_entry"`
	Extensions   CTExtensions		`json:"extensions"`
}

type MerkleTreeLeaf struct {
	Version          Version			`json:"version"`
	LeafType         MerkleLeafType 	`json:"leaf_type"`
	TimestampedEntry *TimestampedEntry	`json:"timestamped_entry"`
}

func (m *MerkleTreeLeaf) X509Certificate() (*x509.Certificate, error) {
	if m.TimestampedEntry.EntryType != X509LogEntryType {
		return nil, fmt.Errorf("cannot call X509Certificate on a MerkleTreeLeaf that is not an X509 entry")
	}
	return x509.ParseCertificate(m.TimestampedEntry.X509Entry.Data)
}

func (m *MerkleTreeLeaf) Precertificate() (*x509.Certificate, error) {
	if m.TimestampedEntry.EntryType != PrecertLogEntryType {
		return nil, fmt.Errorf("cannot call Precertificate on a MerkleTreeLeaf that is not a precert entry")
	}
	return x509.ParseTBSCertificate(m.TimestampedEntry.PrecertEntry.TBSCertificate)
}

type Precertificate struct {
	Submitted ASN1Cert
	IssuerKeyHash [sha256.Size]byte
	TBSCertificate *x509.Certificate
}

type LogEntryType uint64

// LogEntryType constants from section 3.1.
const (
	X509LogEntryType    LogEntryType = 0
	PrecertLogEntryType LogEntryType = 1
)

func (e LogEntryType) String() string {
	switch e {
	case X509LogEntryType:
		return "X509LogEntryType"
	case PrecertLogEntryType:
		return "PrecertLogEntryType"
	default:
		return fmt.Sprintf("UnknownEntryType(%d)", e)
	}
}

const (
	TreeLeafPrefix = byte(0x00)
	TreeNodePrefix = byte(0x01)
)

type LogID struct {
	KeyID [sha256.Size]byte
}

type DigitallySigned tls.DigitallySigned

func (d *DigitallySigned) FromBase64String(b64 string) error {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return fmt.Errorf("failed to unbase64 DigitallySigned: %v", err)
	}
	var ds tls.DigitallySigned
	if rest, err := tls.Unmarshal(raw, &ds); err != nil {
		return fmt.Errorf("failed to unmarshal DigitallySigned: %v", err)
	} else if len(rest) > 0 {
		return fmt.Errorf("trailing data (%d bytes) after DigitallySigned", len(rest))
	}
	*d = DigitallySigned(ds)
	return nil
}

// Base64String returns the base64 representation of the DigitallySigned struct.
func (d DigitallySigned) Base64String() (string, error) {
	b, err := tls.Marshal(d)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

// MarshalJSON implements the json.Marshaller interface.
func (d DigitallySigned) MarshalJSON() ([]byte, error) {
	b64, err := d.Base64String()
	if err != nil {
		return []byte{}, err
	}
	return []byte(`"` + b64 + `"`), nil
}

// UnmarshalJSON implements the json.Unmarshaler interface.
func (d *DigitallySigned) UnmarshalJSON(b []byte) error {
	var content string
	if err := json.Unmarshal(b, &content); err != nil {
		return fmt.Errorf("failed to unmarshal DigitallySigned: %v", err)
	}
	return d.FromBase64String(content)
}

type SignedCertificateTimestamp struct {
	SCTVersion Version
	LogID      LogID
	Timestamp  uint64
	Extensions CTExtensions
	Signature  DigitallySigned
}

type SignatureType uint64

type CertificateTimestamp struct {
	SCTVersion    Version
	SignatureType SignatureType
	Timestamp     uint64
	EntryType     LogEntryType
	X509Entry     *ASN1Cert
	PrecertEntry  *PreCert
	JSONEntry     *JSONDataEntry
	Extensions    CTExtensions
}

func (s SignedCertificateTimestamp) String() string {
	return fmt.Sprintf("{Version:%d LogId:%s Timestamp:%d Extensions:'%s' Signature:%v}", s.SCTVersion,
		base64.StdEncoding.EncodeToString(s.LogID.KeyID[:]),
		s.Timestamp,
		s.Extensions,
		s.Signature)
}

type LogRootV1 struct {
	// TreeSize is the number of leaves in the log Merkle tree.
	TreeSize uint64
	// RootHash is the hash of the root node of the tree.
	RootHash []byte
	// TimestampNanos is the time in nanoseconds for when this root was created,
	// counting from the UNIX epoch.
	TimestampNanos uint64

	// Revision is the Merkle tree revision associated with this root.
	//
	// Deprecated: Revision is a concept internal to the storage layer.
	Revision uint64

	// Metadata holds additional data associated with this root.
	Metadata []byte
}

type LogRoot struct {
	Version tls.Enum
	V1      *LogRootV1
}

// UnmarshalBinary verifies that logRootBytes is a TLS serialized LogRoot, has
// the LOG_ROOT_FORMAT_V1 tag, and populates the caller with the deserialized
// *LogRootV1.
func (l *LogRootV1) UnmarshalBinary(logRootBytes []byte) error {
	if len(logRootBytes) < 3 {
		return fmt.Errorf("logRootBytes too short")
	}
	if l == nil {
		return fmt.Errorf("nil log root")
	}
	version := binary.BigEndian.Uint16(logRootBytes)
	if version != uint16(trillian.LogRootFormat_LOG_ROOT_FORMAT_V1) {
		return fmt.Errorf("invalid LogRoot.Version: %v, want %v",
			version, trillian.LogRootFormat_LOG_ROOT_FORMAT_V1)
	}

	var logRoot LogRoot
	if _, err := tls.Unmarshal(logRootBytes, &logRoot); err != nil {
		return err
	}

	*l = *logRoot.V1
	return nil
}

// MarshalBinary returns a canonical TLS serialization of LogRoot.
func (l *LogRootV1) MarshalBinary() ([]byte, error) {
	return tls.Marshal(LogRoot{
		Version: tls.Enum(trillian.LogRootFormat_LOG_ROOT_FORMAT_V1),
		V1:      l,
	})
}

const (
	CertificateTimestampSignatureType SignatureType = 0
	TreeHashSignatureType             SignatureType = 1
)

func (st SignatureType) String() string {
	switch st {
	case CertificateTimestampSignatureType:
		return "CertificateTimestamp"
	case TreeHashSignatureType:
		return "TreeHash"
	default:
		return fmt.Sprintf("UnknownSignatureType(%d)", st)
	}
}