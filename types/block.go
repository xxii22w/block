package types

import (
	"blocker/crypto"
	"blocker/proto"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"

	"github.com/cbergoon/merkletree"
	pb "github.com/golang/protobuf/proto"
)

type TxHash struct {
	hash []byte
}

func NewTxHash(hash []byte) TxHash {
	return TxHash{hash: hash}
}

func (h TxHash) CalculateHash() ([]byte, error) {
	return h.hash, nil
}

func (h TxHash) Equals(other merkletree.Content) (bool, error) {
	equals := bytes.Equal(h.hash, other.(TxHash).hash)
	return equals, nil
}

func VerifyBlock(b *proto.Block) bool {
	if len(b.Transactions) > 0 {
		if !VerifyRootHash(b) {
			log.Println("INVALID root hash")
			return false
		}
	}
	if len(b.PublicKey) != crypto.PubKeyLen {
		log.Println("INVALID public key length")

		return false
	}
	if len(b.Signature) != crypto.SignatureLen {
		log.Println("INVALID signuture key length")
		return false
	}
	var (
		sig    = crypto.SignatureFromBytes(b.Signature)
		pubKey = crypto.PublicKeyFromBytes(b.PublicKey)
		hash   = HashBlock(b)
	)
	if !sig.Verify(pubKey, hash) {
		fmt.Println(hex.EncodeToString(sig.Bytes()))
		fmt.Println("INVALID signature")
		return false
	}
	return true
}

func SignBlock(pk *crypto.PrivateKey, b *proto.Block) *crypto.Signature {
	// 如果有交易，就创建树根
	if len(b.Transactions) > 0 {
		tree, err := GetMerkeTree(b)
		if err != nil {
			panic(err)
		}
		b.Header.RootHash = tree.MerkleRoot()
	}
	// 在交易时，需要私钥的签名区块
	hash := HashBlock(b)
	sig := pk.Sign(hash)
	b.PublicKey = pk.Public().Bytes()
	b.Signature = sig.Bytes()
	return sig
}

func VerifyRootHash(b *proto.Block) bool {
	tree, err := GetMerkeTree(b)
	if err != nil {
		return false
	}
	valid, err := tree.VerifyTree()
	if err != nil {
		return false
	}

	if !valid {
		return false
	}
	return bytes.Equal(b.Header.RootHash, tree.MerkleRoot())
}

func GetMerkeTree(b *proto.Block) (*merkletree.MerkleTree, error) {
	list := make([]merkletree.Content, len(b.Transactions))
	for i := 0; i < len(b.Transactions); i++ {
		list[i] = NewTxHash(HashTransaction(b.Transactions[i]))
	}
	// Create a new Merkle tree from the list of content
	t, err := merkletree.NewTree(list)
	if err != nil {
		return nil, err
	}

	return t, nil
}

// HashBlock returns a SHA256 of the header.
func HashBlock(block *proto.Block) []byte {
	return HashHeader(block.Header)
}

func HashHeader(header *proto.Header) []byte {
	b, err := pb.Marshal(header)
	if err != nil {
		panic(err)
	}
	hash := sha256.Sum256(b)
	return hash[:]
}
