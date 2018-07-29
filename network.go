package main

import (
	"fmt"
	"net"
	"strings"
	"sync/atomic"

	"github.com/btcsuite/btcd/btcec"
	"github.com/golang/glog"
	"github.com/lightningnetwork/lnd/brontide"
	"github.com/lightningnetwork/lnd/lnwire"
)

type peer struct {
	id   uint32
	addr string
	conn net.Conn
	dial net.Conn
}

func (p *peer) String() string {
	return fmt.Sprintf("%d: %v", p.id, p.addr)
}

type Network struct {
	id   uint32
	host string

	netAddr *lnwire.NetAddress
	priv    *btcec.PrivateKey

	peers map[uint32]*peer
	known map[string]struct{}

	new     chan *peer
	connect chan *peer
	clip    chan string
	errors  chan error
	quit    chan struct{}

	handleClip func(string)
}

func (n *Network) handleInbound(p *peer) {
	noiseConn, ok := p.conn.(*brontide.Conn)
	if !ok {
		n.errors <- fmt.Errorf("unable to switch to brontide")
	}

	addr := p.conn.RemoteAddr()
	glog.Infof("Connected to %s", addr)

	for {
		select {
		case <-n.quit:
			p.conn.Close()
			return
		default:
			msg, err := noiseConn.ReadNextMessage()
			if err != nil {
				n.errors <- fmt.Errorf("Disconnected from %s ", addr)
				return
			}

			str := string(msg)
			glog.Infof("Received from %s: %s", addr, str)

			switch {
			case strings.HasPrefix(str, "addr "):
				addr := strings.TrimPrefix(str, "addr ")
				p.addr = addr
				n.connect <- p

			case strings.HasPrefix(str, "clip "):
				clip := strings.TrimPrefix(str, "clip ")
				n.clip <- clip

			default:
				glog.Errorf("Received unknown message '%s' from %s ", str, addr)
			}
		}
	}
}

func (n *Network) handleOutbound(addr string, conn net.Conn) {
	id := atomic.AddUint32(&n.id, 1)
	n.new <- &peer{
		id:   id,
		addr: addr,
		dial: conn,
	}
}

func (n *Network) dial(addr string) (net.Conn, error) {
	remoteNetAddr, err := getNetAddr(addr)
	if err != nil {
		return nil, err
	}

	conn, err := brontide.Dial(n.priv, remoteNetAddr, net.Dial)
	if err != nil {
		return nil, err
	}
	glog.Infof("Dialing %s", addr)
	return conn, nil
}

func (n *Network) handleMessage() {
	for {
		select {
		case peer := <-n.new:
			n.peers[peer.id] = peer
			n.known[peer.addr] = struct{}{}

		case peer := <-n.connect:
			if _, ok := n.known[peer.addr]; ok {
				break
			}
			conn, err := n.dial(peer.addr)
			if err != nil {
				glog.Error(err)
				break
			}
			peer.dial = conn
			n.known[peer.addr] = struct{}{}

			msg := "addr " + n.netAddr.String()
			conn.Write([]byte(msg))
			for _, p := range n.peers {
				if p.id == peer.id {
					continue
				}
				msg := "addr " + p.addr
				conn.Write([]byte(msg))
			}

		case clip := <-n.clip:
			if n.handleClip != nil {
				n.handleClip(clip)
			}
		case <-n.quit:
			return
		}
	}
}

func (n *Network) handleListen(listener *brontide.Listener) {
	glog.Infof("Server listening on %s", listener.Addr())

	go n.handleMessage()

	for {
		select {
		case <-n.quit:
			return
		default:
			conn, err := listener.Accept()
			if err != nil {
				glog.Fatal(err)
				continue
			}
			id := atomic.AddUint32(&n.id, 1)
			p := &peer{
				id:   id,
				conn: conn,
			}
			n.new <- p
			go n.handleInbound(p)
		}
	}
}

func (n *Network) newKeyPair() error {
	priv, err := btcec.NewPrivateKey(btcec.S256())
	if err != nil {
		if err != nil {
			return err
		}
	}

	n.priv = priv
	return nil
}

func (n *Network) Listen() error {
	if n.priv == nil {
		if err := n.newKeyPair(); err != nil {
			return err
		}
	}

	// Our listener will be local, and the connection remote.
	listener, err := brontide.NewListener(n.priv, n.host)
	if err != nil {
		if err != nil {
			return err
		}
	}

	go n.handleListen(listener)

	netAddr := &lnwire.NetAddress{
		IdentityKey: n.priv.PubKey(),
		Address:     listener.Addr().(*net.TCPAddr),
	}
	n.netAddr = netAddr
	n.known[n.netAddr.String()] = struct{}{}
	glog.Infof("<%s>: Listening at %s", n.host, n.netAddr)
	return nil
}

func (n *Network) Connect(addr string) error {
	glog.Infof("Attempting to convert: %v", addr)

	conn, err := n.dial(addr)
	if err != nil {
		return err
	}
	msg := "addr " + n.netAddr.String()
	conn.Write([]byte(msg))
	n.handleOutbound(addr, conn)
	return nil
}

func (n *Network) Bootstrap(addrs []string) error {
	for _, addr := range addrs {
		if addr == "" {
			continue
		}
		if err := n.Connect(addr); err != nil {
			return err
		}
	}
	return nil
}

func (n *Network) Broadcast(msg []byte) {
	for _, peer := range n.peers {
		if peer.dial != nil {
			peer.dial.Write([]byte(msg))
		}
	}
}

func (n *Network) Shutdown() {
	for _, peer := range n.peers {
		peer.dial.Close()
	}
	close(n.quit)
}
