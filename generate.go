package main

import (
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcd/btcec"
	"fmt"
)

type Network struct {
	name string
	symbol string
	xpubkey byte
	xprivkey byte
}

var network = map[string]Network {
	"btc": {name: "bitcoin", symbol: "btc", xpubkey: 0x00, xprivkey: 0x80},
	"ltc": {name: "litecoin", symbol: "ltc", xpubkey: 0x30, xprivkey: 0xb0},
}

func (network Network) GetNetworkParams() *chaincfg.Params {
	networkParams := &chaincfg.MainNetParams
	networkParams.PubKeyHashAddrID = network.xpubkey
	networkParams.PrivateKeyID = network.xprivkey
	return networkParams
}

func (network Network) CreateWIF() (*btcutil.WIF, error) {
	secret, err := btcec.NewPrivateKey(btcec.S256())
	if err != nil {
		return nil, err
	}
	// print the secret
	return btcutil.NewWIF(secret, network.GetNetworkParams(), true)
}

func (network Network) GetAddress(wif *btcutil.WIF) (*btcutil.AddressPubKey, error) {
	return btcutil.NewAddressPubKey(wif.PrivKey.PubKey().SerializeCompressed(), network.GetNetworkParams())
}

func main() {
	wif, _ := network["btc"].CreateWIF()
	fmt.Printf("wif output (private key): %s\n", wif.String())
	address, _ := network["btc"].GetAddress(wif)
	fmt.Printf("(BTC) getAddress: %s\n", address.EncodeAddress())

	ltcAddress, _ := network["ltc"].GetAddress(wif)
	fmt.Printf("(LTC) getAddress: %s\n", ltcAddress.EncodeAddress())
}