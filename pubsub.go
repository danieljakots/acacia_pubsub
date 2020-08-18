package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"log/syslog"
	"net/http"
	"os"
	"os/exec"
	"strings"
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

type config struct {
	CertPath string
	KeyPath  string
	CaPath   string
	Address  string
	// channel: command
	Actions map[string]string
}

func (rcs *redisConnStatus) setState(state string) {
	rcs.mu.Lock()
	rcs.state = state
	rcs.mu.Unlock()
	log.Println(state)
}

func (rcs *redisConnStatus) getState() string {
	rcs.mu.Lock()
	state := rcs.state
	rcs.mu.Unlock()
	return state
}

func (rcs *redisConnStatus) stateToHttp(w http.ResponseWriter, req *http.Request) {
	fmt.Fprintf(w, "state: %s\n", rcs.getState())
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

func getTLSMaterialPaths(certPath string, keyPath string, caPath string) (
	tls.Certificate, x509.CertPool, error) {
	keyPair, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return tls.Certificate{}, x509.CertPool{}, err
	}

	caCert, err := ioutil.ReadFile(caPath)
	if err != nil {
		return tls.Certificate{}, x509.CertPool{}, err
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)
	return keyPair, *caCertPool, nil
}

func getTLSMaterial(certPath string, keyPath string, caPath string) (
	tls.Certificate, x509.CertPool) {
	keyPair, caCertPool, err := getTLSMaterialVars()
	// if there's an err, we ignore it and we try ..Paths()
	if err == nil {
		log.Println("Loading TLS keys through vars")
		return keyPair, caCertPool
	}
	keyPair, caCertPool, err = getTLSMaterialPaths(certPath, keyPath,
		caPath)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("Loading TLS keys through files")
	return keyPair, caCertPool
}

func retry(rcs *redisConnStatus, config *config, err error) {
	log.Println(err)
	rcs.setState("disconnected")
	time.Sleep(betweenReconnect)
	daemon(rcs, config)
}

func daemon(rcs *redisConnStatus, config *config) {
	keyPair, caCertPool := getTLSMaterial(config.CertPath, config.KeyPath,
		config.CaPath)
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{keyPair},
		RootCAs: &caCertPool}
	dialOpt := radix.DialUseTLS(tlsConfig)
	conn, err := radix.Dial("tcp", config.Address, dialOpt)
	if err != nil {
		retry(rcs, config, err)
	}

	rcs.setState("connected")

	ps := radix.PubSub(conn)
	defer ps.Close() // this will close Conn as well

	msgCh := make(chan radix.PubSubMessage)
	for pubsubChan, _ := range config.Actions {
		if err := ps.Subscribe(msgCh, pubsubChan); err != nil {
			retry(rcs, config, err)
		}
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
			if err := handlePubsubMessage(msg, config.Actions); err != nil {
				retry(rcs, config, err)
			}
		case err := <-errCh:
			retry(rcs, config, err)
		}
	}
}

func handlePubsubMessage(msg radix.PubSubMessage,
	chanCommand map[string]string) error {
	command := strings.Fields(chanCommand[msg.Channel])
	command = append(command, string(msg.Message))
	e := exec.Command(command[0], command[1:]...)
	_, err := e.Output()
	log.Println(strings.Join(command, " "))
	if err != nil {
		return err
	}
	return nil
}

func initSyslog() {
	syslogger, err := syslog.New(syslog.LOG_INFO|syslog.LOG_DAEMON,
		"acacia_pubsub")
	if err != nil {
		log.Fatal(err)
	}
	log.SetOutput(syslogger)
	// Remove the date prefix, it's already in syslog header
	log.SetFlags(0)
}

func readConfig(configPath string) *config {
	configFile, err := ioutil.ReadFile(configPath)
	if err != nil {
		log.Fatal(err)
	}
	var config config
	if err := json.Unmarshal(configFile, &config); err != nil {
		log.Fatal(err)
	}
	return &config
}

func main() {
	initSyslog()
	config := readConfig("/etc/acacia.json")
	rcs := &redisConnStatus{}
	http.HandleFunc("/status", rcs.stateToHttp)
	go http.ListenAndServe(":8091", nil)
	daemon(rcs, config)
}
