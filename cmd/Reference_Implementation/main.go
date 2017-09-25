package main

import (
	"flag"
	"log"

	"github.com/orijtech/prunehorst"
)

func main() {
	var sign bool
	var secretKey string
	var msg string
	flag.StringVar(&secretKey, "sk", "", "the secret key to use")
	flag.StringVar(&msg, "message", "", "the message to use")
	flag.BoolVar(&sign, "sign", false, "sign the message")
	flag.Parse()

	N := prunehorst.N
	LOGC := 6
	LOGT := 17
	K := 54
	PKLEN := N * (1 << uint(LOGC))
	SKLEN := 2 * N
	SIGLEN := (K * N) + (K * (LOGT - LOGC) * N) + N

	var err error
	var pubKey, sk, pk, sm []byte
	pubKey = make([]byte, PKLEN)

	var message []byte
	if len(msg) == 0 {
		message = make([]byte, prunehorst.N)
		for i := range message {
			message[i] = byte(i)
		}
	} else {
		message = []byte(msg)
	}
	mlen := len(message)
	sk = make([]byte, 64)

	SIGN := func() {
		if sm, err = prunehorst.Sign([]byte(message), sk); err != nil {
			log.Fatalf("sign: %v", err)
		}
	}

	CLEANUP := func() {
		sk = make([]byte, SKLEN)
		pk = make([]byte, PKLEN)
		sm = make([]byte, mlen+SIGLEN)
	}

	VERIFY := func() {
		if err := prunehorst.Verify(message, sm, pubKey); err != nil {
			log.Fatalf("verify: %v", err)
		}
	}

	genpk := func(pk, sk []byte, i int) {
		dk, err := prunehorst.PubKey(sk)
		if err != nil {
			log.Fatalf("pubKey #%d: %v", i, err)
		}
		copy(pk, dk)
	}

	genpk(pubKey, sk, 1)

	SIGN()
	VERIFY()
	CLEANUP()

	for i := range sk {
		sk[i] = 0x01
	}
	genpk(pubKey, sk, 2)

	SIGN()
	VERIFY()
	CLEANUP()

	for i := range sk {
		sk[i] = 0xff
	}
	genpk(pubKey, sk, 3)
	SIGN()
	VERIFY()
}
