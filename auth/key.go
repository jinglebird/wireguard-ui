package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/mergermarket/go-pkcs7"
	"io"
	"os"
	"strings"
)

const AdminKeyName = "ADMIN_KEY"

const ClientKeyName = "KEY"

type apiKey struct {
	key     []byte
	keyName string
}

type APIKeyService interface {
	// Encrypt encrypts the given plain text with the specified key.
	Encrypt(unencrypted string) (string, error)

	// Decrypt decrypts the given cipher text with the specified key.
	Decrypt(cipherText string) (string, error)

	// KeyName Key return the key that is used on the current instance.
	KeyName() string

	// SetKey Set the key by the given key name.
	SetKey(keyName string) error
}

// NewKeyService New returns the new api ket struct for encrypting and decrypting.
func NewKeyService(keyName string) (APIKeyService, error) {

	// validate the given keyname.
	err := validateKeyName(keyName)

	if err != nil {
		return nil, err
	}

	// Read the key from an environment variable with the given keyname.
	key := []byte(os.Getenv(keyName))

	return &apiKey{
		key:     key,
		keyName: keyName,
	}, nil
}

func (s *apiKey) KeyName() string {
	return s.keyName
}

// Encrypt takes a keyname and an unencrypted string as input,
// and returns an encrypted string and an error as output.
func (s *apiKey) Encrypt(unencrypted string) (string, error) {

	// Pad the input string using PKCS#7 padding to a multiple of the block size (16 bytes for AES).
	plainText := []byte(unencrypted)
	plainText, err := pkcs7.Pad(plainText, aes.BlockSize)
	if err != nil {
		// Return an error if there was a problem with the padding.
		return "", fmt.Errorf(`plainText: "%s" has error`, plainText)
	}

	// Check if the input string has the correct block size, and return an error if it doesn't.
	if len(plainText)%aes.BlockSize != 0 {
		err := fmt.Errorf(`plainText: "%s" has the wrong block size`, plainText)
		return "", err
	}

	// Create a new AES cipher with the given key.
	block, err := aes.NewCipher(s.key)
	if err != nil {
		return "", err
	}

	// Generate a random initialization vector (IV) and set the first block of the output string to the IV.
	cipherText := make([]byte, aes.BlockSize+len(plainText))
	iv := cipherText[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	// Create a CBC encrypter with the cipher and IV.
	mode := cipher.NewCBCEncrypter(block, iv)

	// Encrypt the padded input string using the CBC encrypter and store the result in the second block of the output string.
	mode.CryptBlocks(cipherText[aes.BlockSize:], plainText)

	// Convert the output string to a hexadecimal string with a colon separator between two 16-byte blocks.
	cipherString := fmt.Sprintf("%x", cipherText)

	return cipherString[:32] + ":" + cipherString[32:], nil
}

// Decrypt takes an encrypted string and a keyname as input,
// and returns a decrypted string and an error as output.
func (s *apiKey) Decrypt(cipherText string) (string, error) {

	// Split the input string into an initialization vector (IV) and a ciphertext string.
	arr := strings.Split(cipherText, ":")

	iv := arr[0]

	// Decode the encrypted key and the IV from hexadecimal strings.
	bKey := []byte(s.key)
	bIV, e := hex.DecodeString(iv)
	if e != nil {
		return "", e
	}

	// Decode the ciphertext from a hexadecimal string.
	cipherTextDecoded, err := hex.DecodeString(arr[1])
	if err != nil {
		return "", err
	}

	// Create a new AES cipher with the decrypted key.
	block, err := aes.NewCipher(bKey)
	if err != nil {
		return "", err
	}

	// Create a CBC decrypter with the cipher and IV.
	mode := cipher.NewCBCDecrypter(block, bIV)

	// Decrypt the ciphertext using the CBC decrypter.
	// Note that we pass the same slice for both input and output to mode.CryptBlocks.
	// This is allowed by the CryptBlocks function, and it decrypts the ciphertext in place.
	mode.CryptBlocks([]byte(cipherTextDecoded), []byte(cipherTextDecoded))

	// Convert the decrypted string to a regular string and truncate it to 24 bytes.
	text := string(cipherTextDecoded)
	return text[0:24], nil

}

func (s *apiKey) SetKey(keyName string) error {
	// validate the given keyname.
	err := validateKeyName(keyName)

	if err != nil {
		return err
	}

	// Read the key from an environment variable with the given keyname.
	s.key = []byte(os.Getenv(keyName))

	return nil
}

func validateKeyName(k string) error {
	if k == AdminKeyName || k == ClientKeyName {
		return nil
	}
	return errors.New("invalid key name")
}
