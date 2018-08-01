package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"strings"

	"github.com/btcsuite/btcd/btcec"
	"github.com/golang/glog"
	"github.com/tuxcanfly/clipboard"
)

func main() {
	flag.Set("logtostderr", "true")

	// process other flags
	hostFlag := flag.String("host", "localhost", "host to listen to")
	portFlag := flag.Int("port", 3000, "port to listen to")
	peersFlag := flag.String("peers", "", "peers to connect to")
	keyFlag := flag.String("key", "", "brontide private key hex")
	flag.Parse()

	host := *hostFlag
	port := *portFlag
	key := *keyFlag
	peers := strings.Split(*peersFlag, ",")

	if host == "localhost" {
		var err error
		host, err = getDefaultHost()
		if err != nil {
			glog.Fatal(err)
			return
		}
	}
	host = fmt.Sprintf("%v:%d", host, port)

	var priv *btcec.PrivateKey
	if key != "" {
		b, err := hex.DecodeString(key)
		if err != nil {
			glog.Fatal(err)
			return
		}
		priv, _ = btcec.PrivKeyFromBytes(btcec.S256(), b)
	}

	network := &Network{
		host:       host,
		priv:       priv,
		peers:      make(map[uint32]*peer),
		known:      make(map[string]struct{}),
		new:        make(chan *peer),
		connect:    make(chan *peer),
		clip:       make(chan string),
		errors:     make(chan error),
		handleClip: func(clip string) { clipboard.WriteAll(clip) },
	}

	if err := network.Listen(); err != nil {
		glog.Fatal(err)
		return
	}

	if err := network.Bootstrap(peers); err != nil {
		glog.Fatal(err)
		return
	}

	changes := make(chan string, 10)
	quit := make(chan struct{})

	go clipboard.MonitorAll(changes, quit)

	for {
		select {
		case <-quit:
			break
		default:
			change, ok := <-changes
			if !ok {
				break
			}
			glog.Infof("%s", change)

			msg := "clip " + change
			network.Broadcast([]byte(msg))
		}
	}
}
