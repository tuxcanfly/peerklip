package main

import (
	"encoding/hex"
	"fmt"
	"net"
	"strings"

	"github.com/btcsuite/btcd/btcec"
	"github.com/lightningnetwork/lnd/lnwire"
)

func getNetAddr(peer string) (*lnwire.NetAddress, error) {
	addr := strings.Split(peer, "@")

	if len(addr) != 2 {
		return nil, fmt.Errorf("Invalid peer addr: %v", peer)
	}

	pubHex, err := hex.DecodeString(addr[0])
	if err != nil {
		return nil, fmt.Errorf("unable to decode str: %v", err)
	}

	pubKey, err := btcec.ParsePubKey(pubHex, btcec.S256())
	if err != nil {
		return nil, fmt.Errorf("unable to parse pubkey: %v", err)
	}

	tcpAddr, err := net.ResolveTCPAddr("tcp", addr[1])
	if err != nil {
		return nil, fmt.Errorf("unable to resolve tcp addr: %v", err)
	}

	// Finally, with all the information parsed,
	// we'll return this fully valid address as a
	// connection attempt.
	netAddr := &lnwire.NetAddress{
		IdentityKey: pubKey,
		Address:     tcpAddr,
	}
	return netAddr, nil
}

func getDefaultHost() (string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	for _, i := range ifaces {
		if i.Flags&net.FlagUp != net.FlagUp {
			continue
		}
		addrs, err := i.Addrs()
		if err != nil {
			return "", err
		}
		for _, addr := range addrs {
			switch v := addr.(type) {
			case *net.IPNet:
				if v.IP.IsLoopback() {
					break
				}
				if p4 := v.IP.To4(); len(p4) == net.IPv4len {
					return v.IP.String(), nil
				}
			}
		}
	}
	return "", nil
}
