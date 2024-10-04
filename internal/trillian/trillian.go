package trillian

import (
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/appliedbits/sti-ct/internal/types"

	trillian "github.com/google/trillian"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/durationpb"
)

// initLog initializes a new log if it doesn't exist.
func InitLog(cfg *types.Config) error {
	ctx, cancel := context.WithTimeout(context.Background(), cfg.LogConnectionTimeout)
	defer cancel()

	conn, err := grpc.DialContext(ctx, cfg.TLogAdminEndpoint, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return fmt.Errorf("failed to connect to Trillian admin endpoint: %v", err)
	}
	defer conn.Close()

	adminClient := trillian.NewTrillianAdminClient(conn)

	// Check if the log already exists
	req := &trillian.GetTreeRequest{TreeId: cfg.TLogID}
	_, err = adminClient.GetTree(ctx, req)
	if err == nil {
		// Log already exists
		return nil
	}

	// Create a new log
	tree := &trillian.Tree{
		TreeState:          trillian.TreeState_ACTIVE,
		TreeType:           trillian.TreeType_LOG,
		DisplayName:        "STI CT Log",
		Description:        "CT Log for Secure Telephone Identity",
		MaxRootDuration:    durationpb.New(24 * time.Hour),
	}
	createdTree, err := adminClient.CreateTree(ctx, &trillian.CreateTreeRequest{Tree: tree})
	if err != nil {
		return fmt.Errorf("failed to create new Trillian log: %v", err)
	}

	cfg.TLogID = createdTree.TreeId
	return initLogTree(cfg)
}

// initLogTree initializes the log tree.
func initLogTree(cfg *types.Config) error {
	ctx, cancel := context.WithTimeout(context.Background(), cfg.LogConnectionTimeout)
	defer cancel()

	conn, err := grpc.DialContext(ctx, cfg.TLogEndpoint, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return fmt.Errorf("failed to connect to Trillian log endpoint: %v", err)
	}
	defer conn.Close()

	client := trillian.NewTrillianLogClient(conn)
	_, err = client.InitLog(ctx, &trillian.InitLogRequest{LogId: cfg.TLogID})
	if err != nil {
		return fmt.Errorf("failed to initialize Trillian log: %v", err)
	}

	return nil
}

func GetCTLogID(pk crypto.PublicKey) ([sha256.Size]byte, error) {
	pubBytes, err := x509.MarshalPKIXPublicKey(pk)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	return sha256.Sum256(pubBytes), nil
}