package models

import "github.com/appliedbits/sti-ct/internal/types"

type AddPreCertificateChain struct {
    Chain      []string `json:"chain"`
}

type AddChainResponse struct {
    SCTVersion types.Version    `json:"sct_version"`
    LogID         []byte        `json:"logid"`
    Timestamp  uint64           `json:"timestamp"`
    Extensions string           `json:"extensions"`
    Signature  []byte           `json:"signature"`
}