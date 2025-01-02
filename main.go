package main

import (
	cryptorand "crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"os"
	"path"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/spf13/cobra"
	"k8s.io/apiserver/pkg/authentication/serviceaccount"
)

func main() {
	cmd, err := makeCmd()
	if err != nil {
		slog.Error("Failed to initialize command", "error", err)
		os.Exit(1)
	}

	if err := cmd.Execute(); err != nil {
		slog.Error("Encountered a fatal error during execution", "error", err)
		os.Exit(1)
	}
}

func makeCmd() (*cobra.Command, error) {
	var (
		oneshot        bool
		aud            string
		serviceAccount string
		namespace      string
		podName        string
		dirPath        string
	)
	cmd := &cobra.Command{
		RunE: func(cmd *cobra.Command, args []string) error {
			return run(
				oneshot,
				aud,
				serviceAccount,
				namespace,
				podName,
				dirPath,
			)
		},
	}
	cmd.Flags().StringVar(&aud, "audience", "", "audience for the generated token")
	if err := cmd.MarkFlagRequired("audience"); err != nil {
		return nil, fmt.Errorf("marking audience flag as required: %w", err)
	}
	cmd.Flags().StringVar(&serviceAccount, "service-account", "my-service-account", "service account name")
	cmd.Flags().StringVar(&namespace, "namespace", "my-namespace", "namespace")
	cmd.Flags().StringVar(&podName, "pod-name", "my-pod-name", "pod name")
	cmd.Flags().StringVar(&dirPath, "output-dir", ".", "directory to write keys and tokens to")
	cmd.Flags().BoolVar(&oneshot, "oneshot", false, "exit after writing the first token")

	return cmd, nil
}

func run(
	oneshot bool,
	aud string,
	serviceAccount string,
	namespace string,
	podName string,
	dirPath string,
) error {
	key, err := readOrCreateKey(dirPath)
	if err != nil {
		return fmt.Errorf("reading or creating key: %w", err)
	}

	staticKeyID := "my-key-id"
	signer, err := jose.NewSigner(jose.SigningKey{
		Key:       key,
		Algorithm: jose.RS256,
	}, &jose.SignerOptions{
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			"kid": staticKeyID,
		},
	})

	jwks := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{
				Key:       key.Public(),
				Algorithm: "RS256",
				KeyID:     staticKeyID,
			},
		},
	}
	jwksBytes, err := json.Marshal(jwks)
	if err != nil {
		return fmt.Errorf("marshaling JWKS: %w", err)
	}
	if err := os.WriteFile(
		path.Join(dirPath, "jwks.json"), jwksBytes, 0644,
	); err != nil {
		return fmt.Errorf("writing JWKS: %w", err)
	}

	for {
		slog.Info("Signing token and writing to disk...")
		tokenPath := path.Join(dirPath, "token")
		tok, err := makeToken(
			signer,
			aud,
			namespace,
			serviceAccount,
			podName,
		)
		if err != nil {
			return fmt.Errorf("making token: %w", err)
		}
		err = os.WriteFile(tokenPath, []byte(tok), 0644)
		if err != nil {
			return fmt.Errorf("writing token: %w", err)
		}
		slog.Info("Wrote token to disk", "path", tokenPath)

		if oneshot {
			slog.Info("Success! Exiting due to one-shot mode.")
			break
		}

		slog.Info("Will write a new token in 1 minute")
		select {
		case <-time.After(time.Minute):
		}
	}

	return nil
}

func readOrCreateKey(dirPath string) (*rsa.PrivateKey, error) {
	privateKeyPath := path.Join(dirPath, "private-key.pem")
	slog.Info("Attempting to load keypair from disk", "path", privateKeyPath)
	data, err := os.ReadFile(privateKeyPath)
	if err == nil {
		block, _ := pem.Decode(data)
		if block == nil {
			return nil, fmt.Errorf("decoding private key: %w", err)
		}
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parsing private key: %w", err)
		}
		slog.Info("Loaded existed keypair from disk")
		return parsed.(*rsa.PrivateKey), nil
	}
	slog.Info("Failed to load existing keypair, will generate one!", "error", err)

	key, err := rsa.GenerateKey(cryptorand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generating RSA key: %w", err)
	}
	encodedKey, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshaling private key: %w", err)
	}
	keyPemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: encodedKey,
	})
	if err := os.WriteFile(
		privateKeyPath, keyPemBytes, 0644,
	); err != nil {
		return nil, fmt.Errorf("writing private key: %w", err)
	}
	slog.Info("Wrote generated keypair to disk")

	return key, nil

}

func makeToken(
	signer jose.Signer,
	aud string,
	ns string,
	sa string,
	podName string,
) (string, error) {
	pc := &privateClaims{
		Kubernetes: kubernetes{
			Namespace: ns,
			Svcacct: ref{
				Name: sa,
				UID:  "00000000-0000-0000-0000-000000000000",
			},
			Pod: &ref{
				Name: podName,
				UID:  "00000000-0000-0000-1111-000000000000",
			},
		},
	}

	now := time.Now()
	ttl := time.Minute * 5
	sc := &jwt.Claims{
		Subject:   serviceaccount.MakeUsername(ns, sa),
		Audience:  jwt.Audience{aud},
		IssuedAt:  jwt.NewNumericDate(now),
		NotBefore: jwt.NewNumericDate(now),
		Expiry:    jwt.NewNumericDate(now.Add(ttl)),
	}

	b := jwt.Signed(signer).Claims(sc).Claims(pc)
	tok, err := b.Serialize()
	if err != nil {
		return "", fmt.Errorf("serializing token: %w", err)
	}
	return tok, nil
}

// Borrowed from https://github.com/kubernetes/kubernetes/blob/master/pkg/serviceaccount/claims.go
type privateClaims struct {
	Kubernetes kubernetes `json:"kubernetes.io,omitempty"`
}

type kubernetes struct {
	Namespace string           `json:"namespace,omitempty"`
	Svcacct   ref              `json:"serviceaccount,omitempty"`
	Pod       *ref             `json:"pod,omitempty"`
	Secret    *ref             `json:"secret,omitempty"`
	Node      *ref             `json:"node,omitempty"`
	WarnAfter *jwt.NumericDate `json:"warnafter,omitempty"`
}

type ref struct {
	Name string `json:"name,omitempty"`
	UID  string `json:"uid,omitempty"`
}
