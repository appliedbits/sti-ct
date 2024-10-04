package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/appliedbits/sti-ct/internal/handlers"
	"github.com/appliedbits/sti-ct/internal/service"
	tr "github.com/appliedbits/sti-ct/internal/trillian"
	"github.com/appliedbits/sti-ct/internal/types"

	"github.com/gin-gonic/gin"
	"github.com/google/certificate-transparency-go/x509util"
	"github.com/google/trillian"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func setupCtLog(cfg *types.Config) (*types.LogInfo, error) {
	signer, _, err := service.LoadKeysFromFile(cfg.KeysPath)
	if err != nil {
		log.Fatalf("Failed to load keys: %v\n", err)
	}

	if cfg.TLogID <= 0 {
		return nil, fmt.Errorf("tree_id must be provided and positive, got %d", cfg.TLogID)
	}

	err = tr.InitLog(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize log: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), cfg.LogConnectionTimeout)
	defer cancel()
	conn, err := grpc.DialContext(ctx, cfg.TLogEndpoint, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("did not connect to trillian on %v: %v\n", cfg.TLogEndpoint, err)
	}

	logClient := trillian.NewTrillianLogClient(conn)

	// Load the trusted roots.
	roots := x509util.NewPEMCertPool()
	files, err := os.ReadDir(cfg.TrustedRootsPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read trusted roots directory: %v", err)
	}

	for _, file := range files {
		if file.IsDir() {
			continue
		}
		if file.Name() == "..data" {
			continue
		}
		pemFile := filepath.Join(cfg.TrustedRootsPath, file.Name())
		log.Printf("Loading trusted roots from %s\n", pemFile)
		pemData, err := os.ReadFile(pemFile)
		if err != nil {
			log.Fatalf("failed to read trusted root file %s: %v\n", pemFile, err)
		}
		if ok := roots.AppendCertsFromPEM(pemData); !ok {
			log.Fatalf("failed to append certs from PEM file %s\n", pemFile)
		}
	}

	return &types.LogInfo{
		LogClient:    logClient,
		Signer:       signer,
		TrustedRoots: roots,
		TLogID:       cfg.TLogID,
	}, nil
}

func main() {
	cfg := &types.Config{
		TrustedRootsPath:     service.GetEnv("TRUSTED_ROOTS_PATH", "/etc/roots"),
		LogConnectionTimeout: service.GetEnvAsDuration("LOG_CONNECTION_TIMEOUT", 10*time.Second),
		TLogEndpoint:         service.GetEnv("TRILLIAN_LOG_SERVER", "trillian-log-server:8090"),
		TLogAdminEndpoint:    service.GetEnv("TRILLIAN_LOG_ADMIN_SERVER", "trillian-log-server:8090"),
		TLogID:               service.GetEnvAsInt64("TRILLIAN_LOG_ID", 1),
		KeysPath:             service.GetEnv("KEYS_PATH", "path/to/keys"),
	}

	logInfo, err := setupCtLog(cfg)
	if err != nil {
		log.Fatalf("Failed to setup CT log: %v", err)
	}

    router := gin.Default()

    // Define routes
    router.POST("/ct/v1/add-pre-chain", handlers.AddPreCertificateChain(logInfo))
    router.GET("/ct/v1/get-sth", handlers.GetSignedTreeHead(logInfo))
    router.GET("/ct/v1/get-sth-consistency", handlers.GetSTHConsistency(logInfo))
    router.GET("/ct/v1/get-proof-by-hash", handlers.GetProofByHash(logInfo))
    router.GET("/ct/v1/get-entries", handlers.GetEntries(logInfo))
    router.GET("/ct/v1/get-roots", handlers.GetRoots(logInfo))
    router.GET("/ct/v1/get-entry-and-proof", handlers.GetEntryAndProof(logInfo))
	router.GET("/healthz", handlers.HealthzHandler)

	port := os.Getenv("SERVER_PORT")
	if port == "" {
		port = "9009" // Default port if not specified
	}

    // Start server
    if err := router.Run(":" + port); err != nil {
        log.Fatalf("Failed to run server: %v", err)
    }
}
