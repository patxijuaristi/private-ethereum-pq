// Copyright 2014 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package crypto

import (
	"crypto/ecdsa"
	"errors"
	"hash"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	crypto_ecdsa "github.com/ethereum/go-ethereum/crypto_modular/ecdsa"
	crypto_sphincs "github.com/ethereum/go-ethereum/crypto_modular/sphincs"
)

// Hardcoded algorithm, to be extended
type Algorithm int64

const (
	ECDSA Algorithm = iota
	SPHINCS
	OTHER
)

func (a Algorithm) String() string {
	switch a {
	case ECDSA:
		return "ECDSA"
	case SPHINCS:
		return "SPHINCS"
	}
	return "error"
}

var actualAlgorithm = "SPHINCS"

var contGenerateKey = 0

// SignatureLength indicates the byte length required to carry a signature with recovery id.
const SignatureLength = 64 + 1 // 64 bytes ECDSA signature + 1 byte recovery id

// RecoveryIDOffset points to the byte offset within the signature that contains the recovery id.
const RecoveryIDOffset = 64

// DigestLength sets the signature digest exact length
const DigestLength = 32

var (
	secp256k1N, _ = new(big.Int).SetString("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16)
)

var errInvalidPubkey = errors.New("invalid secp256k1 public key")

// KeccakState wraps sha3.state. In addition to the usual hash methods, it also supports
// Read to get a variable amount of data from the hash state. Read is faster than Sum
// because it doesn't copy the internal state, but also modifies the internal state.
type KeccakState interface {
	hash.Hash
	Read([]byte) (int, error)
}

// NewKeccakState creates a new KeccakState
func NewKeccakState() KeccakState {
	switch actualAlgorithm {
	case "ECDSA":
		return crypto_ecdsa.NewKeccakState()
	case "SPHINCS":
		return crypto_sphincs.NewKeccakState()
	default:
		return crypto_ecdsa.NewKeccakState()
	}
}

// HashData hashes the provided data using the KeccakState and returns a 32 byte hash
func HashData(kh KeccakState, data []byte) (h common.Hash) {
	switch actualAlgorithm {
	case "ECDSA":
		return crypto_ecdsa.HashData(kh, data)
	case "SPHINCS":
		return crypto_sphincs.HashData(kh, data)
	default:
		return crypto_ecdsa.HashData(kh, data)
	}
}

// Keccak256 calculates and returns the Keccak256 hash of the input data.
func Keccak256(data ...[]byte) []byte {
	switch actualAlgorithm {
	case "ECDSA":
		return crypto_ecdsa.Keccak256(data...)
	case "SPHINCS":
		return crypto_sphincs.Keccak256(data...)
	default:
		return crypto_ecdsa.Keccak256(data...)
	}
}

// Keccak256Hash calculates and returns the Keccak256 hash of the input data,
// converting it to an internal Hash data structure.
func Keccak256Hash(data ...[]byte) (h common.Hash) {
	switch actualAlgorithm {
	case "ECDSA":
		return crypto_ecdsa.Keccak256Hash(data...)
	case "SPHINCS":
		return crypto_sphincs.Keccak256Hash(data...)
	default:
		return crypto_ecdsa.Keccak256Hash(data...)
	}
}

// Keccak512 calculates and returns the Keccak512 hash of the input data.
func Keccak512(data ...[]byte) []byte {
	switch actualAlgorithm {
	case "ECDSA":
		return crypto_ecdsa.Keccak512(data...)
	case "SPHINCS":
		return crypto_sphincs.Keccak512(data...)
	default:
		return crypto_ecdsa.Keccak512(data...)
	}
}

// CreateAddress creates an ethereum address given the bytes and the nonce
func CreateAddress(b common.Address, nonce uint64) common.Address {
	switch actualAlgorithm {
	case "ECDSA":
		return crypto_ecdsa.CreateAddress(b, nonce)
	case "SPHINCS":
		return crypto_sphincs.CreateAddress(b, nonce)
	default:
		return crypto_ecdsa.CreateAddress(b, nonce)
	}
}

// CreateAddress2 creates an ethereum address given the address bytes, initial
// contract code hash and a salt.
func CreateAddress2(b common.Address, salt [32]byte, inithash []byte) common.Address {
	switch actualAlgorithm {
	case "ECDSA":
		return crypto_ecdsa.CreateAddress2(b, salt, inithash)
	case "SPHINCS":
		return crypto_sphincs.CreateAddress2(b, salt, inithash)
	default:
		return crypto_ecdsa.CreateAddress2(b, salt, inithash)
	}
}

// ToECDSA creates a private key with the given D value.
func ToECDSA(d []byte) (*ecdsa.PrivateKey, error) {
	switch actualAlgorithm {
	case "ECDSA":
		return crypto_ecdsa.ToECDSA(d)
	case "SPHINCS":
		return crypto_sphincs.ToECDSA(d)
	default:
		return crypto_ecdsa.ToECDSA(d)
	}
}

// ToECDSAUnsafe blindly converts a binary blob to a private key. It should almost
// never be used unless you are sure the input is valid and want to avoid hitting
// errors due to bad origin encoding (0 prefixes cut off).
func ToECDSAUnsafe(d []byte) *ecdsa.PrivateKey {
	switch actualAlgorithm {
	case "ECDSA":
		return crypto_ecdsa.ToECDSAUnsafe(d)
	case "SPHINCS":
		return crypto_sphincs.ToECDSAUnsafe(d)
	default:
		return crypto_ecdsa.ToECDSAUnsafe(d)
	}
}

// FromECDSA exports a private key into a binary dump.
func FromECDSA(priv *ecdsa.PrivateKey) []byte {
	switch actualAlgorithm {
	case "ECDSA":
		return crypto_ecdsa.FromECDSA(priv)
	case "SPHINCS":
		return crypto_sphincs.FromECDSA(priv)
	default:
		return crypto_ecdsa.FromECDSA(priv)
	}
}

// UnmarshalPubkey converts bytes to a secp256k1 public key.
func UnmarshalPubkey(pub []byte) (*ecdsa.PublicKey, error) {
	switch actualAlgorithm {
	case "ECDSA":
		return crypto_ecdsa.UnmarshalPubkey(pub)
	case "SPHINCS":
		return crypto_sphincs.UnmarshalPubkey(pub)
	default:
		return crypto_ecdsa.UnmarshalPubkey(pub)
	}
}

func FromECDSAPub(pub *ecdsa.PublicKey) []byte {
	switch actualAlgorithm {
	case "ECDSA":
		return crypto_ecdsa.FromECDSAPub(pub)
	case "SPHINCS":
		return crypto_sphincs.FromECDSAPub(pub)
	default:
		return crypto_ecdsa.FromECDSAPub(pub)
	}
}

// HexToECDSA parses a secp256k1 private key.
func HexToECDSA(hexkey string) (*ecdsa.PrivateKey, error) {
	switch actualAlgorithm {
	case "ECDSA":
		return crypto_ecdsa.HexToECDSA(hexkey)
	case "SPHINCS":
		return crypto_sphincs.HexToECDSA(hexkey)
	default:
		return crypto_ecdsa.HexToECDSA(hexkey)
	}
}

// LoadECDSA loads a secp256k1 private key from the given file.
func LoadECDSA(file string) (*ecdsa.PrivateKey, error) {
	switch actualAlgorithm {
	case "ECDSA":
		return crypto_ecdsa.LoadECDSA(file)
	case "SPHINCS":
		return crypto_sphincs.LoadECDSA(file)
	default:
		return crypto_ecdsa.LoadECDSA(file)
	}
}

// SaveECDSA saves a secp256k1 private key to the given file with
// restrictive permissions. The key data is saved hex-encoded.
func SaveECDSA(file string, key *ecdsa.PrivateKey) error {
	switch actualAlgorithm {
	case "ECDSA":
		return crypto_ecdsa.SaveECDSA(file, key)
	case "SPHINCS":
		return crypto_sphincs.SaveECDSA(file, key)
	default:
		return crypto_ecdsa.SaveECDSA(file, key)
	}
}

// GenerateKey generates a new private key.
func GenerateKey() (*ecdsa.PrivateKey, error) {
	contGenerateKey = contGenerateKey + 1
	print("\n===================================\n")
	print(" - GenerateKey n =", contGenerateKey)
	print("\n===================================\n")
	switch actualAlgorithm {
	case "ECDSA":
		return crypto_ecdsa.GenerateKey()
	case "SPHINCS":
		return crypto_sphincs.GenerateKey()
	default:
		return crypto_ecdsa.GenerateKey()
	}
}

// ValidateSignatureValues verifies whether the signature values are valid with
// the given chain rules. The v value is assumed to be either 0 or 1.
func ValidateSignatureValues(v byte, r, s *big.Int, homestead bool) bool {
	switch actualAlgorithm {
	case "ECDSA":
		return crypto_ecdsa.ValidateSignatureValues(v, r, s, homestead)
	case "SPHINCS":
		return crypto_sphincs.ValidateSignatureValues(v, r, s, homestead)
	default:
		return crypto_ecdsa.ValidateSignatureValues(v, r, s, homestead)
	}
}

func PubkeyToAddress(p ecdsa.PublicKey) common.Address {
	switch actualAlgorithm {
	case "ECDSA":
		return crypto_ecdsa.PubkeyToAddress(p)
	case "SPHINCS":
		return crypto_sphincs.PubkeyToAddress(p)
	default:
		return crypto_ecdsa.PubkeyToAddress(p)
	}
}
