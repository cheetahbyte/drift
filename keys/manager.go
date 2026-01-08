package keys

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/crypto/ssh"
)

func Setup(keysDir string, configPrivKey, configPubKey string) (string, error) {
	if err := os.MkdirAll(keysDir, 0o700); err != nil {
		return "", fmt.Errorf("could not create directory for keys: %w", err)
	}

	privateKeyPath := filepath.Join(keysDir, "id_ed25519")
	publicKeyPath := filepath.Join(keysDir, "id_ed25519.pub")

	if configPrivKey != "" {
		privKeyBytes := []byte(configPrivKey)
		if err := os.WriteFile(privateKeyPath, privKeyBytes, 0o600); err != nil {
			return "", fmt.Errorf("could not save the provided private key: %w", err)
		}

		if configPubKey != "" {
			if err := os.WriteFile(publicKeyPath, []byte(configPubKey), 0o644); err != nil {
				return "", fmt.Errorf("could not save the provided public key: %w", err)
			}
		} else {
			if err := recoverPublicKey(privKeyBytes, publicKeyPath); err != nil {
				return "", fmt.Errorf("could not derive the public key from the private one: %w", err)
			}
		}
		return publicKeyPath, nil
	}

	if _, err := os.Stat(privateKeyPath); err == nil {
		if _, err := os.Stat(publicKeyPath); err == nil {
			return publicKeyPath, nil
		}

		existingPrivBytes, err := os.ReadFile(privateKeyPath)
		if err != nil {
			return "", fmt.Errorf("found a private key but couldn't read it: %w", err)
		}
		if err := recoverPublicKey(existingPrivBytes, publicKeyPath); err != nil {
			return "", fmt.Errorf("could not regenerate the missing public key: %w", err)
		}
		return publicKeyPath, nil
	}

	return createKeyPair(privateKeyPath, publicKeyPath)
}

func recoverPublicKey(privKeyBytes []byte, pubPath string) error {
	signer, err := ssh.ParsePrivateKey(privKeyBytes)
	if err != nil {
		return fmt.Errorf("could not parse the private key: %w", err)
	}
	return savePublicKey(pubPath, signer.PublicKey())
}

func createKeyPair(privPath, pubPath string) (string, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", fmt.Errorf("failed to generate new random key: %w", err)
	}

	privBlock, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		return "", fmt.Errorf("failed to format the new private key: %w", err)
	}

	if err := os.WriteFile(privPath, pem.EncodeToMemory(privBlock), 0o600); err != nil {
		return "", fmt.Errorf("could not save the new private key to disk: %w", err)
	}

	sshPubKey, err := ssh.NewPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("failed to create public key object: %w", err)
	}

	if err := savePublicKey(pubPath, sshPubKey); err != nil {
		return "", fmt.Errorf("could not save the new public key to disk: %w", err)
	}

	return pubPath, nil
}

func savePublicKey(path string, key ssh.PublicKey) error {
	pubBytes := ssh.MarshalAuthorizedKey(key)
	return os.WriteFile(path, pubBytes, 0o644)
}

func GetPublicKey(path string) (ssh.PublicKey, error) {
	pubBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read public key file: %w", err)
	}

	pubKey, _, _, _, err := ssh.ParseAuthorizedKey(pubBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	return pubKey, nil
}
