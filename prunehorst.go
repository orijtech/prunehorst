// Copyright 2017 Kudelski Security and orijtech, Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package prunehorst

import (
	"errors"
	"fmt"
	"math"
	"strings"
)

// New constructs a PRUNE-HORST cipher. Its parameters:
// Set Size T must be a power of 2
// Subset size K, which must be lower than T
// Number of subtrees C, which must be strictly lower than T
//
// The parameters determine:
//   * The public key size = 32C bytes
//   * The signature size  = 32 * (K + K(log2(T) - log2(C)) + 1)
// T and K together determine the security and signature length, while
// C determines the public key and signature lengths but not security.
//
// The choice of T and K depends on the target security level and on
// the maximum number of messages to be signed. The security level for
// a given in 3.2.
// The choice of C is mostly a trade-off between the public key size
// that is (higher with a higher C) and the signature size
// that is (smaller with a higher C). The optimal value of C for a given
// (T, K) is discussed in 4.2.
func New(T, C, K int) (*ph, error) {
	var errList []string
	if !powerOf2(T) {
		errList = append(errList, fmt.Sprintf("T must be a power of 2, got: %d", T))
	}
	if K >= T {
		errList = append(errList, "K must be less than T")
	}
	if !powerOf2(C) || C >= T {
		errList = append(errList, "C must be a power of 2 and less than T")
	}
	if len(errList) > 0 {
		return nil, errors.New(strings.Join(errList, "\n"))
	}
	log2C := int(math.Log2(float64(C)))
	log2T := int(math.Log2(float64(T)))
	publicKeyLen := N * C

	p := &ph{
		t: T,
		c: C,
		k: K,

		log2T: log2T,
		log2C: log2C,

		_SKLEN:       2 * N,
		streamLen:    8 * K,
		publicKeyLen: publicKeyLen,

		ekLen: N * T,

		sigLen: (K * N) + (K * (log2T - log2C) * N) + N,
	}

	return p, nil
}

func powerOf2(x int) bool {
	return x != 0 && (x&(x-1)) == 0
}

type ph struct {
	t         int
	k         int
	c         int
	log2T     int
	log2C     int
	_SKLEN    int
	streamLen int

	sigLen int
	ekLen  int

	publicKeyLen int
}

var defaultPH, _ = New(1<<17, 1<<6, 54)

// KeyPair generates a public and private key pair
func (p *ph) KeyPair() (publicKey, privateKey []byte, err error) {
	secretKey, err := randomBytes(p._SKLEN)
	if err != nil {
		return nil, nil, err
	}
	publicKey, err = p.PubKey(secretKey)
	if err != nil {
		return nil, nil, err
	}
	return publicKey, secretKey, nil
}

func PubKey(secretKey []byte) ([]byte, error) {
	return defaultPH.PubKey(secretKey)
}

// KeyPair uses the default PruneHorst cipher to generate a public and private key pair
func KeyPair() (publicKey, privateKey []byte, err error) {
	return defaultPH.KeyPair()
}

// Sign uses the default PruneHorst cipher to sign the message with the secret key
func Sign(message, secretKey []byte) ([]byte, error) {
	return defaultPH.cryptoSign(message, secretKey)
}

func (p *ph) Sign(message, secretKey []byte) ([]byte, error) {
	return p.cryptoSign(message, secretKey)
}

// Verify uses the default PruneHorst cipher to verify the signedMessage
func Verify(message, signedMessage, publicKey []byte) error {
	return defaultPH.cryptoSignOpen(message, signedMessage, publicKey)
}

func (p *ph) Verify(message, signedMessage, publicKey []byte) error {
	return p.cryptoSignOpen(message, signedMessage, publicKey)
}
