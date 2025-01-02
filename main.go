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
	key, err := rsa.GenerateKey(cryptorand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("generating RSA key: %w", err)
	}
	encodedKey, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return fmt.Errorf("marshaling private key: %w", err)
	}
	keyPemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: encodedKey,
	})
	if err := os.WriteFile(
		path.Join(dirPath, "private-key.pem"), keyPemBytes, 0644,
	); err != nil {
		return fmt.Errorf("writing private key: %w", err)
	}

	signer, err := jose.NewSigner(jose.SigningKey{
		Key:       key,
		Algorithm: jose.RS256,
	}, &jose.SignerOptions{})

	jwks := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{
				Key: key.Public(),
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
		tok, err := makeToken(signer)
		if err != nil {
			return fmt.Errorf("making token: %w", err)
		}
		err = os.WriteFile(path.Join(dirPath, "token"), []byte(tok), 0644)
		if err != nil {
			return fmt.Errorf("writing token: %w", err)
		}

		if oneshot {
			break
		}

		select {
		case <-time.After(time.Minute):
		}
	}

	return nil
}

func makeToken(signer jose.Signer) (string, error) {
	ns := "default"
	sa := "my-service-account"

	pc := &privateClaims{
		Kubernetes: kubernetes{
			Namespace: ns,
			Svcacct: ref{
				Name: sa,
				UID:  "58456cb0-0000-0000-0000-5578fdceaced",
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
