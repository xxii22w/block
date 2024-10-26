package main

import (
	"blocker/crypto"
	"blocker/node"
	"blocker/proto"
	"blocker/util"
	"context"
	"log"
	"time"

	"google.golang.org/grpc"
)

func main() {

	// 发现会链接到一棵树上 5000->4000 那么 5000->3000
	makeNode(":3000", []string{},true)
	time.Sleep(time.Second)
	makeNode(":4000", []string{":3000"},false)
	time.Sleep(4 * time.Second)
	makeNode(":5000", []string{":4000"},false)

	for {
		time.Sleep(time.Second)
		makeTransaction()
	}
	
}

func makeNode(listenAddr string, bootstrapNodes []string,isValidator bool) *node.Node {
	cfg := node.ServerConfig{
		Version: "Blocker-1",
		ListenAddr: listenAddr,
	}
	if isValidator {
		cfg.PrivateKey = crypto.GeneratePrivateKey()
	}

	n := node.NewNode(cfg)
	go n.Start(listenAddr, bootstrapNodes)
	return n
}

func makeTransaction() {
	client, err := grpc.Dial(":3000", grpc.WithInsecure())
	if err != nil {
		log.Fatal(err)
	}

	c := proto.NewNodeClient(client)
	privKey := crypto.GeneratePrivateKey()

	tx := &proto.Transaction{
		Version: 1,
		Inputs: []*proto.TxInput{
			{
				PrevTxHash:   util.RandomHash(),
				PrevOutIndex: 0,
				PublicKey:    privKey.Public().Bytes(),
			},
		},
		Outputs: []*proto.TxOutput{
			{
				Amount:  99,
				Address: privKey.Public().Address().Bytes(),
			},
		},
	}

	_, err = c.HandleTransaction(context.TODO(), tx)
	if err != nil {
		log.Fatal(err)
	}
}
