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

package prunehorst_test

import (
	"fmt"
	"log"

	"github.com/orijtech/prunehorst"
)

func Example_KeyPair() {
	pubKey, privKey, err := prunehorst.KeyPair()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("PubKey: %x\nPrivKey: %x\n", pubKey, privKey)
}

func Example_KeyPair_Custom() {
	ph, err := prunehorst.New(1<<17, 1<<6, 54)
	if err != nil {
		log.Fatal(err)
	}
	pubKey, privKey, err := ph.KeyPair()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("PubKey: %x\nPrivKey: %x\n", pubKey, privKey)
}

func Example_Sign() {
	_, sk, _ := prunehorst.KeyPair()
	signature, err := prunehorst.Sign([]byte("This is a sample"), sk)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Signature: %x\n", signature)
}

func Example_Verify() {
	pubKey, privKey, err := prunehorst.KeyPair()
	if err != nil {
		log.Fatal(err)
	}
	plainText := []byte("This is PostQuantum crypto, true")
	signature, err := prunehorst.Sign(plainText, privKey)
	if err != nil {
		log.Fatal(err)
	}

	// ...
	// Sent over the wire or asked for a verification
	signedMessage := signature[:]
	if err := prunehorst.Verify(plainText, signedMessage, pubKey); err != nil {
		log.Fatal(err)
	}
	log.Printf("Successfully verified the message!")
}
