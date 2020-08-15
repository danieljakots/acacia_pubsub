package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"log/syslog"
	"net/http"
	"os"
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
	fmt.Fprintf(w, "state: %s\n", rcs.state)
	rcs.mu.Unlock()
}

func getTLSMaterialVars() (tls.Certificate, x509.CertPool, error) {
	cert := []byte(os.Getenv("_acacia_cert"))
	key := []byte(os.Getenv("_acacia_key"))
	caCert := []byte(os.Getenv("_acacia_ca"))
	if len(cert) == 0 || len(key) == 0 || len(caCert) == 0 {
		return tls.Certificate{}, x509.CertPool{},
			errors.New("Couldn't load tls material from env")
	}

	keyPair, err := tls.X509KeyPair(cert, key)
	if err != nil {
		return tls.Certificate{}, x509.CertPool{}, err
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)
	return keyPair, *caCertPool, nil
}

func getTLSMaterialPaths() (tls.Certificate, x509.CertPool, error) {
	keyPair, err := tls.LoadX509KeyPair("/etc/ssl/chownme.crt",
		"/etc/ssl/private/chownme.key")
	if err != nil {
		return tls.Certificate{}, x509.CertPool{}, err
	}

	caCert, err := ioutil.ReadFile("/etc/ssl/chownme-cacert.pem")
	if err != nil {
		return tls.Certificate{}, x509.CertPool{}, err
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)
	return keyPair, *caCertPool, nil
}

func getTLSMaterial() (tls.Certificate, x509.CertPool) {
	keyPair, caCertPool, err := getTLSMaterialVars()
	// if there's an err, we ignore it and we try ..Paths()
	if err == nil {
		log.Println("Loading TLS keys through vars")
		return keyPair, caCertPool
	}
	keyPair, caCertPool, err = getTLSMaterialPaths()
	if err != nil {
		log.Fatal(err)
	}
	log.Println("Loading TLS keys through files")
	return keyPair, caCertPool
}

func (rcs *redisConnStatus) daemon() {
	keyPair, caCertPool := getTLSMaterial()
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{keyPair},
		RootCAs: &caCertPool}
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
