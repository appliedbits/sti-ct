package handlers

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/appliedbits/sti-ct/internal/models"
	tr "github.com/appliedbits/sti-ct/internal/trillian"
	"github.com/appliedbits/sti-ct/internal/types"

	"github.com/gin-gonic/gin"
	"github.com/google/certificate-transparency-go/tls"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/trillian"
)

// AddPreCertificateChain handles the "add-pre-chain" requests.
func AddPreCertificateChain(logInfo *types.LogInfo) gin.HandlerFunc {
	return func(c *gin.Context) {
		var addChainReq models.AddPreCertificateChain
		if err := c.BindJSON(&addChainReq); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
			return
		}

		var rawChain [][]byte
		for _, cert := range addChainReq.Chain {
			rawCert, err := base64.StdEncoding.DecodeString(cert)
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Failed to decode certificate: %s", err)})
				return
			}
			rawChain = append(rawChain, rawCert)
		}
		chain, err := parseCertificateChain(rawChain)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Failed to parse certificate chain: %s", err)})
			return
		}

		// Verify the pre-certificate chain.
		if err := verifyPreCertificateChain(logInfo, chain); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Pre-certificate chain verification failed: %s", err)})
			return
		}

		// Create the LogLeaf structure to submit.
		timeMillis := uint64(time.Now().UnixNano() / 1e6)
		leaf, err := buildPreCertLogLeaf(chain, timeMillis)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to build MerkleTreeLeaf: %s", err)})
			return
		}

		// Queue the leaf entry in the log.
		req := &trillian.QueueLeafRequest{
			LogId: logInfo.TLogID,
			Leaf:  leaf,
		}
		rsp, err := logInfo.LogClient.QueueLeaf(context.Background(), req)
		if err != nil || rsp.QueuedLeaf == nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to queue the pre-certificate leaf"})
			return
		}

		var loggedLeaf types.MerkleTreeLeaf
		if rest, err := tls.Unmarshal(rsp.QueuedLeaf.Leaf.LeafValue, &loggedLeaf); err != nil {
			c.JSON(http.StatusInternalServerError, fmt.Errorf("failed to reconstruct MerkleTreeLeaf: %s", err))
			return
		} else if len(rest) > 0 {
			c.JSON(http.StatusInternalServerError, fmt.Errorf("extra data (%d bytes) on reconstructing MerkleTreeLeaf", len(rest)))
			return
		}

		// Generate SCT for the submitted pre-certificate.
		sct, err := buildPreCertificateSCT(logInfo.Signer, &loggedLeaf)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to generate SCT: %s", err)})
			return
		}

		c.JSON(http.StatusOK, sct)
	}
}

// parseCertificateChain converts a slice of raw DER certificate bytes into a slice of x509.Certificate objects.
func parseCertificateChain(rawChain [][]byte) ([]*x509.Certificate, error) {
    var chain []*x509.Certificate
    for _, rawCert := range rawChain {
        cert, err := x509.ParseCertificate(rawCert)
        if err != nil {
            return nil, fmt.Errorf("failed to parse certificate: %s", err)
        }
        chain = append(chain, cert)
    }
    return chain, nil
}

// verifyPreCertificateChain performs pre-certificate chain verification based on trusted roots.
func verifyPreCertificateChain(li *types.LogInfo, chain []*x509.Certificate) error {
	opts := x509.VerifyOptions{
		Roots: li.TrustedRoots.CertPool(),
	}
	if _, err := chain[0].Verify(opts); err != nil {
		return fmt.Errorf("failed to verify pre-certificate chain: %s", err)
	}
	return nil
}

// isPreIssuer indicates whether a certificate is a pre-cert issuer with the specific
// certificate transparency extended key usage.
func isPreIssuer(issuer *x509.Certificate) bool {
	for _, eku := range issuer.ExtKeyUsage {
		if eku == x509.ExtKeyUsageCertificateTransparency {
			return true
		}
	}
	return false
}

// buildPreCertLogLeaf constructs a Merkle tree leaf entry for the pre-certificate.
func buildPreCertLogLeaf(chain []*x509.Certificate, timestamp uint64) (*trillian.LogLeaf, error) {
    if len(chain) < 2 {
		return nil, fmt.Errorf("no issuer cert available for precert leaf building")
	}
	issuer := chain[1]
	cert := chain[0]

	var preIssuer *x509.Certificate
	if isPreIssuer(issuer) {
		// Replace the cert's issuance information with details from the pre-issuer.
		preIssuer = issuer

		// The issuer of the pre-cert is not going to be the issuer of the final
		// cert.  Change to use the final issuer's key hash.
		if len(chain) < 3 {
			return nil, fmt.Errorf("no issuer cert available for pre-issuer")
		}
		issuer = chain[2]
	}

	// Next, post-process the DER-encoded TBSCertificate, to remove the CT poison
	// extension and possibly update the issuer field.
	defangedTBS, err := x509.BuildPrecertTBS(cert.RawTBSCertificate, preIssuer)
	if err != nil {
		return nil, fmt.Errorf("failed to remove poison extension: %v", err)
	}

	preCert := &types.PreCert{
		IssuerKeyHash:  sha256.Sum256(issuer.RawSubjectPublicKeyInfo),
		TBSCertificate: defangedTBS,
	}

    // Construct the Merkle leaf.
    leaf := &types.MerkleTreeLeaf{
        Version: types.V1,
        LeafType: types.TimestampedEntryLeafType,
        TimestampedEntry: &types.TimestampedEntry{
            Timestamp:    timestamp,
            EntryType:    types.PrecertLogEntryType,
            PrecertEntry: preCert,
        },
    }

    leafBytes, err := tls.Marshal(leaf)
    if err != nil {
        return nil, fmt.Errorf("failed to marshal MerkleTreeLeaf: %s", err)
    }

    logLeaf := &trillian.LogLeaf{
        LeafValue: leafBytes,
    }

    return logLeaf, nil
}

// buildPreCertificateSCT creates a SignedCertificateTimestamp for the pre-certificate.
func buildPreCertificateSCT(signer crypto.Signer, leaf *types.MerkleTreeLeaf) (*types.SignedCertificateTimestamp, error) {
	if leaf.TimestampedEntry.EntryType != types.PrecertLogEntryType {
		return nil, fmt.Errorf("unsupported entry type: %s", leaf.TimestampedEntry.EntryType)
	}

	sctInput := types.CertificateTimestamp{
		SCTVersion:    types.V1,
		SignatureType: types.CertificateTimestampSignatureType,
		Timestamp:     leaf.TimestampedEntry.Timestamp,
		EntryType:     leaf.TimestampedEntry.EntryType,
		PrecertEntry: &types.PreCert{
			IssuerKeyHash:  leaf.TimestampedEntry.PrecertEntry.IssuerKeyHash,
			TBSCertificate: leaf.TimestampedEntry.PrecertEntry.TBSCertificate,
		},
		Extensions: leaf.TimestampedEntry.Extensions,
	}

	// Marshal the SCT signature input using TLS
	data, err := tls.Marshal(sctInput)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize SCT data: %v", err)
	}

	// Hash the serialized data
	h := sha256.Sum256(data)
	signature, err := signer.Sign(rand.Reader, h[:], crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("failed to sign SCT data: %v", err)
	}

	// Construct the DigitallySigned structure
	digitallySigned := types.DigitallySigned{
		Algorithm: tls.SignatureAndHashAlgorithm{
			Hash:      tls.SHA256,
			Signature: tls.SignatureAlgorithmFromPubKey(signer.Public()),
		},
		Signature: signature,
	}

	// Get the log ID
	logID, err := tr.GetCTLogID(signer.Public())
	if err != nil {
		return nil, fmt.Errorf("failed to get logID for signing: %v", err)
	}

	// Return the SignedCertificateTimestamp
	return &types.SignedCertificateTimestamp{
		SCTVersion: types.V1,
		LogID:      types.LogID{KeyID: logID},
		Timestamp:  sctInput.Timestamp,
		Extensions: sctInput.Extensions,
		Signature:  digitallySigned,
	}, nil
}

// writeSCTResponse marshals the SCT to JSON and writes it to the HTTP response.
func writeSCTResponse(w http.ResponseWriter, sct *types.SignedCertificateTimestamp) (int, error) {
    w.Header().Set("Content-Type", "application/json")
    jsonSCT, err := json.Marshal(sct)
    if err != nil {
        return http.StatusInternalServerError, fmt.Errorf("failed to marshal SCT: %s", err)
    }

    if _, err = w.Write(jsonSCT); err != nil {
        return http.StatusInternalServerError, fmt.Errorf("failed to write SCT response: %s", err)
    }

    return http.StatusOK, nil
}

// GetSignedTreeHead handles the "get-sth" requests.
func GetSignedTreeHead(logInfo *types.LogInfo) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Request the Signed Tree Head (STH) from the log.
		req := &trillian.GetLatestSignedLogRootRequest{LogId: logInfo.TLogID}
		resp, err := logInfo.LogClient.GetLatestSignedLogRoot(context.Background(), req)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve signed tree head"})
			return
		}

		var sth types.LogRootV1
		if err := sth.UnmarshalBinary(resp.SignedLogRoot.LogRoot); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to unmarshal signed tree head"})
			return
		}

		c.JSON(http.StatusOK, sth)
	}
}

// GetSTHConsistency handles the "get-sth-consistency" requests.
func GetSTHConsistency(logInfo *types.LogInfo) gin.HandlerFunc {
	return func(c *gin.Context) {
		first, err := strconv.ParseInt(c.Query("first"), 10, 64)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid 'first' parameter"})
			return
		}

		second, err := strconv.ParseInt(c.Query("second"), 10, 64)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid 'second' parameter"})
			return
		}

		// Request consistency proof.
		req := &trillian.GetConsistencyProofRequest{
			LogId:          logInfo.TLogID,
			FirstTreeSize:  first,
			SecondTreeSize: second,
		}
		resp, err := logInfo.LogClient.GetConsistencyProof(context.Background(), req)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve consistency proof"})
			return
		}

		c.JSON(http.StatusOK, resp)
	}
}

// GetProofByHash handles the "get-proof-by-hash" requests.
func GetProofByHash(logInfo *types.LogInfo) gin.HandlerFunc {
	return func(c *gin.Context) {
		leafHash := c.Query("hash")
		hashBytes, err := base64.StdEncoding.DecodeString(leafHash)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid hash parameter"})
			return
		}

		treeSize, err := strconv.ParseInt(c.Query("tree_size"), 10, 64)
		if err != nil || treeSize < 1 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tree size parameter"})
			return
		}

		// Request proof by hash.
		req := &trillian.GetInclusionProofByHashRequest{
			LogId:    logInfo.TLogID,
			LeafHash: hashBytes,
			TreeSize: treeSize,
		}
		resp, err := logInfo.LogClient.GetInclusionProofByHash(context.Background(), req)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve proof by hash"})
			return
		}

		c.JSON(http.StatusOK, resp)
	}
}

// GetEntries handles the "get-entries" requests.
func GetEntries(logInfo *types.LogInfo) gin.HandlerFunc {
	return func(c *gin.Context) {
		start, err := strconv.ParseInt(c.Query("start"), 10, 64)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid 'start' parameter"})
			return
		}

		end, err := strconv.ParseInt(c.Query("end"), 10, 64)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid 'end' parameter"})
			return
		}

		req := &trillian.GetLeavesByRangeRequest{
			LogId:      logInfo.TLogID,
			StartIndex: start,
			Count:      end - start + 1,
		}
		resp, err := logInfo.LogClient.GetLeavesByRange(context.Background(), req)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve log entries"})
			return
		}

		c.JSON(http.StatusOK, resp)
	}
}

// GetRoots handles the "get-roots" requests.
func GetRoots(logInfo *types.LogInfo) gin.HandlerFunc {
	return func(c *gin.Context) {
		roots := logInfo.TrustedRoots.RawCertificates()
		c.JSON(http.StatusOK, roots)
	}
}

// GetEntryAndProof handles the "get-entry-and-proof" requests.
func GetEntryAndProof(logInfo *types.LogInfo) gin.HandlerFunc {
	return func(c *gin.Context) {
		leafIndex, err := strconv.ParseInt(c.Query("leaf_index"), 10, 64)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid 'leaf_index' parameter"})
			return
		}

		treeSize, err := strconv.ParseInt(c.Query("tree_size"), 10, 64)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid 'tree_size' parameter"})
			return
		}

		req := &trillian.GetEntryAndProofRequest{
			LogId:     logInfo.TLogID,
			LeafIndex: leafIndex,
			TreeSize:  treeSize,
		}
		resp, err := logInfo.LogClient.GetEntryAndProof(context.Background(), req)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve entry and proof"})
			return
		}

		c.JSON(http.StatusOK, resp)
	}
}

// HealthzHandler is a simple health check endpoint.
func HealthzHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "healthy"})
}
