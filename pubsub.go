package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"log/syslog"
	"net/http"
	"os/exec"
	"sync"
	"time"

	"github.com/mediocregopher/radix/v3"
)

const (
	betweenPing      = 5 * time.Second
	betweenReconnect = 30 * time.Second
)

type redisConnStatus struct {
	mu    sync.Mutex
	state string
}

func (rcs *redisConnStatus) stateToHttp(w http.ResponseWriter, req *http.Request) {
	rcs.mu.Lock()
	fmt.Println(rcs.state)
	fmt.Fprintf(w, "state: %s\n", rcs.state)
	rcs.mu.Unlock()
}

func (rcs *redisConnStatus) daemon() {
	keyPair, err := tls.LoadX509KeyPair("/etc/ssl/chownme.crt",
		"/etc/ssl/private/chownme.key")
	if err != nil {
		log.Fatal(err)
	}

	caCert, err := ioutil.ReadFile("/etc/ssl/chownme-cacert.pem")
	if err != nil {
		log.Fatal(err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{keyPair},
		RootCAs: caCertPool}
	dialOpt := radix.DialUseTLS(tlsConfig)
	conn, err := radix.Dial("tcp", "db1.chown.me:6380", dialOpt)
	if err != nil {
		panic(err)
	}

	rcs.mu.Lock()
	rcs.state = "connected"
	rcs.mu.Unlock()
	log.Println("Connected")

	ps := radix.PubSub(conn)
	defer ps.Close() // this will close Conn as well

	msgCh := make(chan radix.PubSubMessage)
	if err := ps.Subscribe(msgCh, "block"); err != nil {
		panic(err)
	}

	errCh := make(chan error, 1)
	go func() {
		ticker := time.NewTicker(betweenPing)
		defer ticker.Stop()
		for range ticker.C {
			if err := ps.Ping(); err != nil {
				errCh <- err
				return
			}
		}
	}()

	for {
		select {
		case msg := <-msgCh:
			handlePubsubMessage(msg)
		case err := <-errCh:
			panic(err)
		}
	}
}

func handlePubsubMessage(msg radix.PubSubMessage) {
	IP := string(msg.Message)
	cmd := exec.Command("/usr/bin/doas", "/sbin/pfctl", "-t", "api_bans",
		"-T", "add", IP)
	_, err := cmd.Output()
	log.Println("blocking", IP)
	if err != nil {
		panic(err)
	}
}

func (rcs *redisConnStatus) tryRecover() {
	if r := recover(); r != nil {
		log.Println("recovered from", r)
		rcs.mu.Lock()
		rcs.state = "disconnected"
		rcs.mu.Unlock()
		log.Println("disconnected")
	}
	time.Sleep(betweenReconnect)
	rcs.loop()
}

func (rcs *redisConnStatus) loop() {
	for {
		defer rcs.tryRecover()
		rcs.daemon()
	}
}

func initSyslog() {
	syslogger, err := syslog.New(syslog.LOG_INFO, "goblock_share")
	if err != nil {
		log.Fatal(err)
	}
	log.SetOutput(syslogger)
	// Remove the date prefix, it's already in syslog header
	log.SetFlags(0)
}

func main() {
	initSyslog()
	rcs := &redisConnStatus{}
	http.HandleFunc("/status", rcs.stateToHttp)
	go http.ListenAndServe(":8091", nil)
	rcs.loop()
}
