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
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"

	"github.com/orijtech/haraka"
)

const (
	N = 32 // N = byte length of hashes, shouldn't change

	_DRBG_IVLEN = 16 // Byte length of DRBG IV (here AES-CTR nonce)

	_BYTES_PER_INDEX = 4
)

func (p *ph) _PATHS(b []byte) []byte {
	return b[N+(p.k*N):]
}

// _DRBG used in subset generation.
// It is AES-256CTR.
func _DRBG(out, key, iv []byte, keyLen int) error {
	// Select AES-256, with 32 bytes of the key
	// Note: Unauthenticated AES256-CTR
	block, err := aes.NewCipher(key[:32])
	if err != nil {
		return err
	}
	counter := make([]byte, 16)
	blockSize := block.BlockSize()
	stream := cipher.NewCTR(block, iv[:blockSize])
	for i := 0; i < len(out); i += blockSize {
		end := i + blockSize
		stream.XORKeyStream(out[i:end], counter)
	}
	return nil
}

func (p *ph) _STREAM_LEN() int {
	return 8 * p.k
}

func (p *ph) getSubset(subset []int, mHash, seed []byte) error {
	K := p.k
	T := p.t
	STREAM_LEN := p._STREAM_LEN()

	toHash := make([]byte, 2*N)
	subsetSeed := make([]byte, N)
	iv := make([]byte, N)
	randStream := make([]byte, STREAM_LEN)

	copy(toHash, seed[:N])
	copy(toHash[N:], mHash[:N])
	haraka.Haraka512(subsetSeed, toHash)

	// memset(iv, 1, DRBG_IVLEN)
	for i := range iv {
		iv[i] = 1
	}
	if err := _DRBG(randStream, subsetSeed, iv, STREAM_LEN); err != nil {
		return err
	}

	if _DEBUG {
		_PBYTES("getsubset: subset seed", subsetSeed, N)
	}

	count := 0
	offset := 0
	for count < K {
		// OK to take mod since T is a power of 2
		pB := u8To32(randStream[offset:])
		index := int(pB) % T
		offset += _BYTES_PER_INDEX
		duplicate := 0
		for i := 0; i < count; i++ {
			if subset[i] == index {
				duplicate += 1
			}
		}

		if duplicate == 0 {
			subset[count] = index
			count += 1
		}
	}
	return nil
}

func u8To32(p []byte) uint32 {
	return (uint32(p[3]) << 24) | (uint32(p[2]) << 16) | (uint32(p[1]) << 8) | (uint32(p[0]))
}

func (p *ph) expandSecretKey(ek, sk []byte) error {
	iv := make([]byte, _DRBG_IVLEN)
	// memset(iv, 0, drbgIVLen)
	return _DRBG(ek, sk, iv, p.ekLen)
}

func (p *ph) PubKey(sk []byte) ([]byte, error) {
	T := p.t
	EKLEN := p.ekLen
	PKLEN := p.publicKeyLen
	LOGT := p.log2T
	LOGC := p.log2C

	if _DEBUG {
		SKLEN := p._SKLEN
		_PBYTES("genpk: sk", sk, SKLEN)
	}

	hashes := T
	ek := make([]byte, EKLEN)
	// expand sk to T subkeys
	if err := p.expandSecretKey(ek, sk); err != nil {
		return nil, err
	}

	if _DEBUG {
		// only show first values to minimize the file size
		_PBYTES("genpk: ek[0..63]", ek, 64)
	}

	// Hash the T hashed subkeys
	for j := 0; j < T; j++ {
		haraka.Haraka256(ek[j*N:], ek[j*N:])
	}

	// Compute the binary hash tree upto level LOGT - LOGC (root if LOGC=0)
	for l := 0; l < LOGT-LOGC; l++ {
		// Halved number of hashes
		hashes /= 2
		for i := 0; i < hashes; i++ {
			haraka.Haraka512(ek[i*N:], ek[2*i*N:])
		}
	}
	if _DEBUG {
		_PBYTES("genpk: pk", ek, PKLEN)
	}
	return ek[:PKLEN], nil
}

func randomBytes(n int) ([]byte, error) {
	bs := make([]byte, n)
	_, err := rand.Reader.Read(bs)
	return bs, err
}

func sha256It(b []byte) []byte {
	h := sha256.New()
	h.Write(b)
	return h.Sum(nil)
}

func padIt(b []byte, n int) []byte {
	if len(b) >= n {
		return b
	}
	return append(bytes.Repeat([]byte{0x00}, n-len(b)), b...)
}

func (p *ph) cryptoSignCached(sm, m, sk2, ek []byte) error {
	K := p.k
	T := p.t
	log2C := p.log2C
	log2T := p.log2T

	mLen := len(m)
	mHash := make([]byte, N)
	// Hash the message with SHA-256
	copy(mHash, sha256It(m))

	if _DEBUG {
		_PBYTES("crypto_sign: mhash", mHash, N)
	}

	toHash := make([]byte, 2*N)
	signatureSeed := make([]byte, N)

	// Compute a subset from the message hash and secret key
	copy(toHash, sk2[:N])
	copy(toHash[N:], mHash[:N])
	haraka.Haraka512(signatureSeed, toHash)

	if _DEBUG {
		_PBYTES("crypto_sign: signature_seed", signatureSeed, N)
	}

	subset := make([]int, K)
	if err := p.getSubset(subset, mHash, signatureSeed); err != nil {
		return err
	}
	copy(sm[mLen:], signatureSeed[:N])

	if _DEBUG {
		_PINTS("crypto_sign: subset", subset, K)
	}

	// Append subkeys from the subset to the signature
	subKeys := _SUBKEYS(sm[mLen:])
	for i := 0; i < K; i++ {
		index := subset[i]
		copy(subKeys[i*N:], ek[index*N:][:N])
	}

	if _DEBUG {
		_PBYTES("crypto_sign: subkeys", subKeys, N*K)
	}

	// Buffer to store the tree's nodes
	buf := make([]byte, T*N)

	// Pointer to the start of auth paths in the signature
	paths := p._PATHS(sm[mLen:])

	// Hash subkeys to get the tree's leaves
	for j := 0; j < T; j++ {
		haraka.Haraka256(buf[j*N:], ek[j*N:])
	}

	// Compute the tree from the leaves, til level LOGC
	hashes := T
	for l := 0; l < log2T-log2C; l++ {
		// Append the sibling to the sig for each of the K subkeys
		for i := 0; i < K; i++ {
			sibling := subset[i] ^ 1
			idx := (K * N * l) + (i * N)
			copy(paths[idx:], buf[sibling*N:][:N])
			subset[i] = subset[i] / 2
		}

		if _DEBUG {
			_PBYTES("crypto_sign: K siblings", paths[K*N*l:], K*N)
		}
		hashes /= 2
		for i := 0; i < hashes; i++ {
			haraka.Haraka512(buf[i*N:], buf[2*i*N:])
		}
	}

	copy(sm, m[:mLen][:N])

	if _DEBUG {
		SIGLEN := p.sigLen
		_PBYTES("crypto_sign: sm+mlen", sm[mLen:], SIGLEN)
	}
	return nil
}

func (p *ph) cryptoSign(message, secretKey []byte) ([]byte, error) {
	EKLEN := p.ekLen
	SIGLEN := p.sigLen

	// Expand secretKey into T subkeys
	ek := make([]byte, EKLEN)
	if err := p.expandSecretKey(ek, secretKey); err != nil {
		return nil, err
	}
	if _DEBUG {
		_PBYTES("crypto_sign: m", message, len(message))
		_PBYTES("crypto_sign: sk", secretKey, 2*N)
	}

	// sm = malloc(N + SIGLEN)
	signedMessage := make([]byte, N+SIGLEN)
	if err := p.cryptoSignCached(signedMessage, message, secretKey[N:], ek); err != nil {
		return nil, err
	}
	return signedMessage, nil
}

var errVerifyRoot = errors.New("failed to verify root")

func (p *ph) cryptoSignOpen(m, sm, publicKey []byte) error {
	K := p.k
	SIGLEN := p.sigLen
	LOGC := p.log2C
	LOGT := p.log2T

	smLen := len(sm)
	mHash := make([]byte, N)
	tmp := make([]byte, N)
	buf := make([]byte, N*2)

	if _DEBUG {
		PKLEN := p.publicKeyLen
		_PBYTES("crypto_sign_open: sm", sm, smLen)
		_PBYTES("crypto_sign_open: pk", publicKey, PKLEN)
	}

	mLen := smLen - SIGLEN

	subKeys := _SUBKEYS(sm[mLen:])
	paths := p._PATHS(sm[mLen:])

	// Sanity checks
	if len(sm) == 0 || len(m) == 0 || len(publicKey) == 0 || smLen < SIGLEN {
		return fmt.Errorf("expecting len(sm)=%d > 0 && len(m)=%d > 0 && len(publicKey)=%d > 0 && smLen=%d >= SIGLEN=%d", len(sm), len(m), len(publicKey), smLen, SIGLEN)
	}

	// Hash the message with SHA-256
	// HASH (mHash, sm, smLen - SIGLEN)
	copy(mHash, sha256It(sm[:mLen]))

	if _DEBUG {
		_PBYTES("crypto_sign_open: mhash", mHash, N)
	}

	subset := make([]int, K)
	if err := p.getSubset(subset, mHash, sm[mLen:]); err != nil {
		return err
	}

	if _DEBUG {
		_PINTS("crypto_sign_open: subset", subset, K)
	}

	// Compute the tree's root for each of the
	// K subset leaves, using nodes from  the auth path.
	for i := 0; i < K; i++ {
		index := subset[i]
		haraka.Haraka256(tmp, subKeys[i*N:])

		for l := 0; l < LOGT-LOGC; l++ {
			if index%2 == 0 {
				copy(buf, tmp[:N])
				copy(buf[N:], paths[(K*N*l)+(i*N):][:N])
			} else {
				copy(buf, paths[(K*N*l)+(i*N):][:N])
				copy(buf[N:], tmp[:N])
			}

			haraka.Haraka512(tmp, buf)
			index = index / 2
		}

		if _DEBUG {
			_PBYTES("crypto_sign_open: root", tmp, N)
		}

		// Check that the root matches the
		// node stored in the publicKey
		//
		// memcmp(pk + (index * N), tmp, N)
		// Compare:
		// + pk[index*N: index*2N]
		// + tmp[:N]
		pkStart := index * N
		pkEnd := pkStart + N
		if !bytes.Equal(publicKey[pkStart:pkEnd], tmp[:N]) {
			// Failed to verify the root
			return errVerifyRoot
		}
	}

	copy(m, sm[:smLen-SIGLEN][:N])
	return nil
}

// _SUBKEYS gives the offset of subkeys in a signature
func _SUBKEYS(s []byte) []byte {
	return s[N:]
}

const shift = 32

var _DEBUG = os.Getenv("DEBUG") != ""

func _PBYTES(msg string, x []byte, xlen int) {
	fmt.Printf("%s (%d):\n", msg, xlen)
	i := 0
	if xlen > len(x) {
		xlen = len(x)
	}
	for {
		end := i + shift
		if end > xlen {
			end = xlen
		}
		fmt.Printf("%x\n", x[i:end])
		i = end
		if i >= xlen {
			fmt.Printf("\n")
			return
		}
	}
}

func _PINTS(msg string, x []int, xlen int) {
	fmt.Printf("%s (%d):\n", msg, xlen)
	for i := 0; i < xlen; i++ {
		fmt.Printf("%d", x[i])
	}
	fmt.Printf("\n\n")
}
