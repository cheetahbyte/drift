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

// Setup prepares the SSH keys needed for git operations.
// It checks if keys were provided manually, if they already exist on disk,
// or creates a fresh pair if nothing is found.
// Formerly: Ensure
func Setup(keysDir string, configPrivKey, configPubKey string) (string, error) {
	// First, let's make sure we have a secure place to put the keys
	if err := os.MkdirAll(keysDir, 0o700); err != nil {
		return "", fmt.Errorf("could not create directory for keys: %w", err)
	}

	privateKeyPath := filepath.Join(keysDir, "id_ed25519")
	publicKeyPath := filepath.Join(keysDir, "id_ed25519.pub")

	// Scenario 1: You gave us specific keys to use (e.g. from environment variables)
	if configPrivKey != "" {
		privKeyBytes := []byte(configPrivKey)
		if err := os.WriteFile(privateKeyPath, privKeyBytes, 0o600); err != nil {
			return "", fmt.Errorf("could not save the provided private key: %w", err)
		}

		// Did you give us a public key too?
		if configPubKey != "" {
			if err := os.WriteFile(publicKeyPath, []byte(configPubKey), 0o644); err != nil {
				return "", fmt.Errorf("could not save the provided public key: %w", err)
			}
		} else {
			// No problem, we can figure it out from the private key
			if err := recoverPublicKey(privKeyBytes, publicKeyPath); err != nil {
				return "", fmt.Errorf("could not derive the public key from the private one: %w", err)
			}
		}
		return publicKeyPath, nil
	}

	// Scenario 2: We found keys already waiting on disk
	if _, err := os.Stat(privateKeyPath); err == nil {
		// Do we have the matching public key?
		if _, err := os.Stat(publicKeyPath); err == nil {
			return publicKeyPath, nil
		}

		// Public key is missing, let's regenerate it from the private key
		existingPrivBytes, err := os.ReadFile(privateKeyPath)
		if err != nil {
			return "", fmt.Errorf("found a private key but couldn't read it: %w", err)
		}
		if err := recoverPublicKey(existingPrivBytes, publicKeyPath); err != nil {
			return "", fmt.Errorf("could not regenerate the missing public key: %w", err)
		}
		return publicKeyPath, nil
	}

	// Scenario 3: No keys found. Let's make a fresh pair.
	return createKeyPair(privateKeyPath, publicKeyPath)
}

// recoverPublicKey calculates the public key from a private key file and saves it
// Formerly: deriveAndSavePublicKey
func recoverPublicKey(privKeyBytes []byte, pubPath string) error {
	signer, err := ssh.ParsePrivateKey(privKeyBytes)
	if err != nil {
		return fmt.Errorf("could not parse the private key: %w", err)
	}
	return savePublicKey(pubPath, signer.PublicKey())
}

// createKeyPair generates a brand new Ed25519 key pair
// Formerly: generateAndSaveKeys
func createKeyPair(privPath, pubPath string) (string, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", fmt.Errorf("failed to generate new random key: %w", err)
	}

	// Convert the private key to a format SSH understands (OpenSSH PEM)
	privBlock, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		return "", fmt.Errorf("failed to format the new private key: %w", err)
	}

	if err := os.WriteFile(privPath, pem.EncodeToMemory(privBlock), 0o600); err != nil {
		return "", fmt.Errorf("could not save the new private key to disk: %w", err)
	}

	// Now handle the public key
	sshPubKey, err := ssh.NewPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("failed to create public key object: %w", err)
	}

	if err := savePublicKey(pubPath, sshPubKey); err != nil {
		return "", fmt.Errorf("could not save the new public key to disk: %w", err)
	}

	return pubPath, nil
}

// savePublicKey writes the public key to disk in the standard authorized_keys format
// Formerly: writePublicKey
func savePublicKey(path string, key ssh.PublicKey) error {
	pubBytes := ssh.MarshalAuthorizedKey(key)
	return os.WriteFile(path, pubBytes, 0o644)
}
