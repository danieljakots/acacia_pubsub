package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
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
	CertPath string
	KeyPath  string
	CaPath   string
	Address  string
	User     string
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

func getTLSMaterialVars() ([]byte, []byte, []byte) {
	cert := []byte(os.Getenv("_acacia_cert"))
	key := []byte(os.Getenv("_acacia_key"))
	caCert := []byte(os.Getenv("_acacia_ca"))
	return cert, key, caCert
}

func getTLSMaterialPaths(certPath string, keyPath string, caPath string) (
	[]byte, []byte, []byte) {
	cert, err := ioutil.ReadFile(certPath)
	if err != nil {
		log.Fatal(err)
	}
	key, err := ioutil.ReadFile(keyPath)
	if err != nil {
		log.Fatal(err)
	}
	caCert, err := ioutil.ReadFile(caPath)
	if err != nil {
		log.Fatal(err)
	}
	return cert, key, caCert
}

func getTLSMaterial(config *config) *tls.Config {
	cert, key, caCert := getTLSMaterialVars()
	if len(cert) == 0 || len(key) == 0 || len(caCert) == 0 {
		log.Println("Couldn't load tls material from env")
		cert, key, caCert = getTLSMaterialPaths(config.CertPath,
			config.KeyPath, config.CaPath)
	}

	keyPair, err := tls.X509KeyPair(cert, key)
	if err != nil {
		log.Fatal(err)
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	tlsConfig := &tls.Config{Certificates: []tls.Certificate{keyPair},
		RootCAs: caCertPool}
	return tlsConfig
}

func retry(rcs *redisConnStatus, config *config, tlsConfig *tls.Config, err error) {
	log.Println(err)
	rcs.setState("disconnected")
	time.Sleep(betweenReconnect)
	daemon(rcs, config, tlsConfig)
}

func daemon(rcs *redisConnStatus, config *config, tlsConfig *tls.Config) {
	dialOpt := radix.DialUseTLS(tlsConfig)
	conn, err := radix.Dial("tcp", config.Address, dialOpt)
	if err != nil {
		retry(rcs, config, tlsConfig, err)
	}

	rcs.setState("connected")

	ps := radix.PubSub(conn)
	defer ps.Close() // this will close Conn as well

	msgCh := make(chan radix.PubSubMessage)
	for pubsubChan, _ := range config.Actions {
		if err := ps.Subscribe(msgCh, pubsubChan); err != nil {
			retry(rcs, config, tlsConfig, err)
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
				retry(rcs, config, tlsConfig, err)
			}
		case err := <-errCh:
			retry(rcs, config, tlsConfig, err)
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

func detectSignal() {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigs
	log.Println("received signal:", sig)
	os.Exit(0)
}

func addFileToEnv(filePath string, envVar string, env []string) []string {
	file, err := ioutil.ReadFile(filePath)
	if err != nil {
		log.Fatal(err)
	}
	env = append(env, fmt.Sprintf("%s=%s", envVar, file))
	return env
}

func getUserAndGroupIds(username string) (uint32, uint32) {
	user, err := user.Lookup(username)
	if err != nil {
		log.Fatal(err)
	}
	uid, err := strconv.ParseInt(user.Uid, 10, 32)
	if err != nil {
		log.Fatal(err)
	}
	gid, err := strconv.ParseInt(user.Gid, 10, 32)
	if err != nil {
		log.Fatal(err)
	}
	return uint32(uid), uint32(gid)
}

func dropPriv(config *config) error {
	/* We load the TLS material, and give it through env to a new process
	ran under unprivileged user*/
	uid, gid := getUserAndGroupIds(config.User)

	env := make([]string, 3)
	env = addFileToEnv(config.CertPath, "_acacia_cert", env)
	env = addFileToEnv(config.KeyPath, "_acacia_key", env)
	env = addFileToEnv(config.CaPath, "_acacia_ca", env)

	cmd := exec.Command(os.Args[0])
	cmd.Env = env
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{Uid: uid, Gid: gid},
		Setsid: true,
	}

	if err := cmd.Start(); err != nil {
		return err
	}

	log.Printf("Spawned process %d, exiting\n", cmd.Process.Pid)
	cmd.Process.Release()
	os.Exit(0)
	return nil /* unreachable */
}

func main() {
	initSyslog()
	go detectSignal()
	config := readConfig("/etc/acacia.json")
	if os.Getuid() == 0 && config.User != "" {
		// main() won't continue after dropPriv(), it will be re-exec
		dropPriv(config)
	}

	log.Println("Continuing startup under euid", os.Geteuid())
	rcs := &redisConnStatus{}
	http.HandleFunc("/status", rcs.stateToHttp)
	go http.ListenAndServe("127.0.0.1:8091", nil)
	log.Println("status page listening on port 8091")
	tlsConfig := getTLSMaterial(config)
	daemon(rcs, config, tlsConfig)
}
