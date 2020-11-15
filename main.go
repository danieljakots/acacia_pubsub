// Copyright (c) 2020 Daniel Jakots

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to
// deal in the Software without restriction, including without limitation the
// rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
// sell copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
// IN THE SOFTWARE.

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
	"os/signal"
	"os/user"
	"strconv"
	"strings"
	"sync"
	"syscall"
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
	CertPath      string
	KeyPath       string
	CaPath        string
	RedisAddress  string
	StatusAddress string
	User          string
	// channel: command
	Actions map[string]string
}

func (rcs *redisConnStatus) setStatus(state string) {
	rcs.mu.Lock()
	rcs.state = state
	rcs.mu.Unlock()
	log.Println(state)
}

func (rcs *redisConnStatus) status() string {
	rcs.mu.Lock()
	state := rcs.state
	rcs.mu.Unlock()
	return state
}

func (rcs *redisConnStatus) stateToHttp(w http.ResponseWriter, req *http.Request) {
	fmt.Fprintf(w, "state: %s\n", rcs.status())
}

func listenStatusPage(statusAddress string) {
	err := http.ListenAndServe(statusAddress, nil)
	if err != nil {
		log.Fatal(err)
	}
}

func getTLSMaterialVars() ([]byte, []byte, []byte, error) {
	cert := []byte(os.Getenv("_acacia_cert"))
	key := []byte(os.Getenv("_acacia_key"))
	caCert := []byte(os.Getenv("_acacia_ca"))
	var err error
	if len(cert) == 0 || len(key) == 0 || len(caCert) == 0 {
		err = errors.New("At least one environment variable is empty")
	}
	return cert, key, caCert, err
}

func getTLSMaterialPaths(certPath string, keyPath string, caPath string) (
	[]byte, []byte, []byte, error) {
	cert, err := ioutil.ReadFile(certPath)
	if err != nil {
		return nil, nil, nil, err
	}
	key, err := ioutil.ReadFile(keyPath)
	if err != nil {
		return nil, nil, nil, err
	}
	caCert, err := ioutil.ReadFile(caPath)
	if err != nil {
		return nil, nil, nil, err
	}
	return cert, key, caCert, err
}

func getTLSMaterial(config *config) (*tls.Config, error) {
	cert, key, caCert, err := getTLSMaterialVars()
	if err != nil {
		log.Println("Couldn't load tls material from env")
		cert, key, caCert, err = getTLSMaterialPaths(config.CertPath,
			config.KeyPath, config.CaPath)
		if err != nil {
			return nil, err
		}
	}

	keyPair, err := tls.X509KeyPair(cert, key)
	if err != nil {
		return nil, err
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	tlsConfig := &tls.Config{Certificates: []tls.Certificate{keyPair},
		RootCAs: caCertPool}
	return tlsConfig, nil
}

func retry(rcs *redisConnStatus, config *config, tlsConfig *tls.Config, err error) {
	log.Println(err)
	rcs.setStatus("disconnected")
	time.Sleep(betweenReconnect)
	daemon(rcs, config, tlsConfig)
}

func heartbeat(ps radix.PubSubConn, errCh chan<- error) {
	ticker := time.NewTicker(betweenPing)
	defer ticker.Stop()
	for range ticker.C {
		if err := ps.Ping(); err != nil {
			errCh <- err
			return
		}
	}
}

func daemon(rcs *redisConnStatus, config *config, tlsConfig *tls.Config) {
	dialOpt := radix.DialUseTLS(tlsConfig)
	conn, err := radix.Dial("tcp", config.RedisAddress, dialOpt)
	if err != nil {
		retry(rcs, config, tlsConfig, err)
	}

	rcs.setStatus("connected")

	ps := radix.PubSub(conn)
	defer ps.Close() // this will close Conn as well

	msgCh := make(chan radix.PubSubMessage)
	for pubsubChan := range config.Actions {
		log.Println("Listening on pubsub channel", pubsubChan)
		if err := ps.Subscribe(msgCh, pubsubChan); err != nil {
			retry(rcs, config, tlsConfig, err)
		}
	}

	errCh := make(chan error, 1)
	go heartbeat(ps, errCh)

	for {
		select {
		case msg := <-msgCh:
			handlePubsubMessage(msg, config.Actions)
		case err := <-errCh:
			retry(rcs, config, tlsConfig, err)
		}
	}
}

func handlePubsubMessage(msg radix.PubSubMessage, chanCommand map[string]string) {
	command := strings.Fields(chanCommand[msg.Channel])
	command = append(command, string(msg.Message))
	e := exec.Command(command[0], command[1:]...)
	_, err := e.Output()
	log.Println("Running command:", strings.Join(command, " "))
	if err != nil {
		log.Println("Running", command, "resulted in error:", err)
	}
}

func initSyslog() error {
	syslogger, err := syslog.New(syslog.LOG_INFO|syslog.LOG_DAEMON,
		"acacia_pubsub")
	if err != nil {
		return err
	}
	log.SetOutput(syslogger)
	// Remove the date prefix, it's already in syslog header
	log.SetFlags(0)
	return nil
}

func readConfig(configPath string) (*config, error) {
	configFile, err := ioutil.ReadFile(configPath)
	if err != nil {
		return nil, err
	}
	var config config
	if err := json.Unmarshal(configFile, &config); err != nil {
		return nil, err
	}
	return &config, nil
}

func detectSignal() {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigs
	log.Printf("received signal: %v, shutting down", sig)
	os.Exit(0)
}

func addFileToEnv(filePath string, envVar string, env []string) ([]string, error) {
	file, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	env = append(env, fmt.Sprintf("%s=%s", envVar, file))
	return env, nil
}

func getUserAndGroupIds(username string) (uint32, uint32, error) {
	user, err := user.Lookup(username)
	if err != nil {
		return 0, 0, err
	}
	uid, err := strconv.ParseInt(user.Uid, 10, 32)
	if err != nil {
		return 0, 0, err
	}
	gid, err := strconv.ParseInt(user.Gid, 10, 32)
	if err != nil {
		return 0, 0, err
	}
	return uint32(uid), uint32(gid), nil
}

func dropPriv(config *config) error {
	/* We load the TLS material, and give it through env to a new process
	run under unprivileged user */
	uid, gid, err := getUserAndGroupIds(config.User)
	if err != nil {
		return err
	}

	env := make([]string, 3)
	env, err = addFileToEnv(config.CertPath, "_acacia_cert", env)
	if err != nil {
		return err
	}
	env, err = addFileToEnv(config.KeyPath, "_acacia_key", env)
	if err != nil {
		return err
	}
	env, err = addFileToEnv(config.CaPath, "_acacia_ca", env)
	if err != nil {
		return err
	}

	cmd := exec.Command(os.Args[0])
	cmd.Env = env
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{Uid: uid, Gid: gid},
		Setsid:     true,
	}

	if err := cmd.Start(); err != nil {
		return err
	}

	log.Printf("Spawned process %d, exiting\n", cmd.Process.Pid)
	cmd.Process.Release()
	os.Exit(0)
	return nil /* unreachable */
}

func configPath(args []string) string {
	if len(args) > 1 {
		return args[1]
	} else {
		return "/etc/acacia.json"
	}
}

func main() {
	err := initSyslog()
	if err != nil {
		log.Fatal(err)
	}
	go detectSignal()
	config, err := readConfig(configPath(os.Args))
	if err != nil {
		log.Fatal(err)
	}
	if os.Getuid() == 0 && config.User != "" {
		// main() won't continue after dropPriv(), it will be re-exec
		err := dropPriv(config)
		if err != nil {
			log.Fatal(err)
		}
	}

	log.Println("Continuing startup under euid", os.Geteuid())
	rcs := &redisConnStatus{}
	http.HandleFunc("/status", rcs.stateToHttp)
	go listenStatusPage(config.StatusAddress)
	log.Println("status page listening on", config.StatusAddress)
	tlsConfig, err := getTLSMaterial(config)
	if err != nil {
		log.Fatal(err)
	}
	daemon(rcs, config, tlsConfig)
}
