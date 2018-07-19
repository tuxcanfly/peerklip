package main

import (
	"flag"
	"strings"
	"time"

	"github.com/golang/glog"
	"github.com/perlin-network/noise/crypto/ed25519"
	"github.com/perlin-network/noise/network"
	"github.com/perlin-network/noise/network/discovery"
	"github.com/perlin-network/noise/network/nat"
	"github.com/shivylp/clipboard"
	"github.com/tuxcanfly/peerklip/messages"
)

// ClipboardPlugin monitors the clipboard and syncs with peers.
type ClipboardPlugin struct{ *network.Plugin }

// Receive receives a message from peers.
func (state *ClipboardPlugin) Receive(ctx *network.PluginContext) error {
	switch msg := ctx.Message().(type) {
	case *messages.KlipMessage:
		glog.Infof("<%s> %s", ctx.Client().ID.Address, msg.Message)
		clipboard.WriteAll(msg.Message)
	}

	return nil
}

func main() {
	// glog defaults to logging to a file, override this flag to log to console for testing
	flag.Set("logtostderr", "true")

	// process other flags
	portFlag := flag.Int("port", 3000, "port to listen to")
	hostFlag := flag.String("host", "localhost", "host to listen to")
	protocolFlag := flag.String("protocol", "tcp", "protocol to use (kcp/tcp)")
	peersFlag := flag.String("peers", "", "peers to connect to")
	natFlag := flag.Bool("nat", false, "enable NAT")
	flag.Parse()

	port := uint16(*portFlag)
	host := *hostFlag
	protocol := *protocolFlag
	peers := strings.Split(*peersFlag, ",")

	keys := ed25519.RandomKeyPair()

	glog.Infof("Private Key: %s", keys.PrivateKeyHex())
	glog.Infof("Public Key: %s", keys.PublicKeyHex())

	builder := network.NewBuilder()
	builder.SetKeys(keys)
	builder.SetAddress(network.FormatAddress(protocol, host, port))

	// Register peer discovery plugin.
	builder.AddPlugin(new(discovery.Plugin))

	// Register NAT plugin.
	if *natFlag {
		nat.RegisterPlugin(builder)
	}

	// Add custom chat plugin.
	builder.AddPlugin(new(ClipboardPlugin))

	net, err := builder.Build()
	if err != nil {
		glog.Fatal(err)
		return
	}

	go net.Listen()

	if len(peers) > 0 {
		net.Bootstrap(peers...)
	}

	changes := make(chan string, 10)
	quit := make(chan struct{})

	go clipboard.Monitor(time.Second, quit, changes)

	for {
		select {
		case <-quit:
			break
		default:
			change, ok := <-changes
			if !ok {
				break
			}
			glog.Infof("<%s> %s", net.Address, change)

			net.Broadcast(&messages.KlipMessage{Message: change})
		}
	}
}
