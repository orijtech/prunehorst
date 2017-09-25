/*
PruneHorst is a stateless hash-based signature scheme designed by
Jean-Phillipe Aumasson and Guillame Endignoux while working in
Kudelski Security's research team

Sample usage:

Generate a keypair

    pubKey, privKey, err := prunehorst.KeyPair()
    if err != nil {
	log.Fatal(err)
    }
    fmt.Printf("PubKey: %x\nPrivKey: %x\n", pubKey, privKey)

Sign something

    signature, err := prunehorst.Sign([]byte("This is post-quantum crypto true"), privKey)
    if err != nil {
	log.Fatal(err)
    }
    fmt.Printf("This is the signature: %x\n", signature)
*/

package prunehorst
