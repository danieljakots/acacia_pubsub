package main

import (
	"bytes"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/mediocregopher/radix/v3"
)

func TestGetTLSMaterialVars(t *testing.T) {
	certShouldbe := "foo"
	keyShouldbe := "bar"
	caCertShouldbe := "baz"
	if err := os.Setenv("_acacia_cert", certShouldbe); err != nil {
		t.Fatal("Setenv failed")
	}
	if err := os.Setenv("_acacia_key", keyShouldbe); err != nil {
		t.Fatal("Setenv failed")
	}
	if err := os.Setenv("_acacia_ca", caCertShouldbe); err != nil {
		t.Fatal("Setenv failed")
	}

	cert, key, caCert, err := getTLSMaterialVars()
	if err != nil {
		t.Error("getTLSMaterialVars() failed")
	}
	if string(cert) != certShouldbe || string(key) != keyShouldbe ||
		string(caCert) != caCertShouldbe {
		t.Error("getTLSMaterialVars() value failed")
	}
}

func TestRedisConnStatus(t *testing.T) {
	rcs := &redisConnStatus{}
	rcs.setStatus("connected")
	if state := rcs.status(); state != "connected" {
		t.Error("status() and or setStatus() failed")
	}
}

func TestStateToHttp(t *testing.T) {
	rcs := &redisConnStatus{}
	rcs.setStatus("connected")

	rec := httptest.NewRecorder()
	req, err := http.NewRequest("GET", "/status", nil)
	if err != nil {
		t.Error("new request failed")
	}
	rcs.stateToHttp(rec, req)

	result := rec.Result()
	if result.StatusCode != http.StatusOK {
		t.Errorf("wrong status code for stateToHttp: got %d, want %d",
			result.StatusCode, http.StatusOK)
	}

	defer result.Body.Close()
	body, err := ioutil.ReadAll(result.Body)
	if err != nil {
		t.Error("reading body failed")
		t.Fatal(err)
	}
	if string(body) != "state: connected\n" {
		t.Errorf("wrong body for stateToHttp: got %q", body)
	}
}

func TestAddFileToEnv(t *testing.T) {
	env := make([]string, 1)
	env, err := addFileToEnv("testdata/nonexistent", "foo", env)
	if err == nil {
		t.Error("addFileToEnv() nonexistent failed")
	}
	env = make([]string, 1)
	env, err = addFileToEnv("testdata/filetoenv", "foo", env)
	if err != nil {
		t.Error("addFileToEnv() err failed")
	}
	if len(env) == 0 {
		t.Error("addFileToEnv() len failed")
	}
	if env[1] != "foo=coincoin\n" {
		t.Error("addFileToEnv() value failed")
	}
}

func TestGetTLSMaterial(t *testing.T) {
	log.SetOutput(ioutil.Discard)
	if err := os.Unsetenv("_acacia_cert"); err != nil {
		t.Fatal("Unsetenv failed")
	}
	configCertFail := &config{CertPath: "testdata/nonexistent",
		KeyPath: "testdata/client.example.com.key",
		CaPath:  "testdata/cacert.pem"}
	tlsConfig, err := getTLSMaterial(configCertFail)
	if err == nil {
		t.Error("getTLSMaterial() CertFail failed")
	}
	configKeyFail := &config{CertPath: "testdata/client.example.com.crt",
		KeyPath: "testdata/nonexistent",
		CaPath:  "testdata/cacert.pem"}
	tlsConfig, err = getTLSMaterial(configKeyFail)
	if err == nil {
		t.Error("getTLSMaterial() KeyFail failed")
	}
	configCaFail := &config{CertPath: "testdata/client.example.com.crt",
		KeyPath: "testdata/client.example.com.key",
		CaPath:  "testdata/nonexistent"}
	tlsConfig, err = getTLSMaterial(configCaFail)
	if err == nil {
		t.Error("getTLSMaterial() CaFail failed")
	}

	config := &config{CertPath: "testdata/client.example.com.crt",
		KeyPath: "testdata/client.example.com.key",
		CaPath:  "testdata/cacert.pem"}
	tlsConfig, err = getTLSMaterial(config)
	if err != nil {
		t.Error("getTLSMaterial() err failed")
	}
	if tlsConfig == nil {
		t.Error("getTLSMaterial() failed")
	}
}

func TestReadConfig(t *testing.T) {
	conf, err := readConfig("acacia.json.nonexistent")
	if err == nil {
		t.Error("readConfig() nonexistent failed")
	}
	conf, err = readConfig("testdata/filetoenv")
	if err == nil {
		t.Error("readConfig() filetoenv failed")
	}
	conf, err = readConfig("acacia.json.sample")
	if err != nil {
		t.Error("readConfig() err failed")
	}
	if conf.RedisAddress != "redis.example.com:6379" {
		t.Error("readConfig() failed")
	}
}

func TestGetUserAndGroupIds(t *testing.T) {
	uid, gid, err := getUserAndGroupIds("nonexistentuser")
	if err == nil {
		t.Error("getUserAndGroupIds() nonexistentuser failed")
	}
	uid, gid, err = getUserAndGroupIds("root")
	if err != nil {
		t.Error("getUserAndGroupIds() err failed")
	}
	if uid != 0 || gid != 0 {
		t.Error("getUserAndGroupIds() failed")
	}
}

func TestHandlePubsubMessage(t *testing.T) {
	msg := radix.PubSubMessage{Channel: "foo", Message: []byte("/nonexistent")}
	chanCommand := make(map[string]string)
	chanCommand["foo"] = "ls"
	var fakeWriter bytes.Buffer
	log.SetOutput(&fakeWriter)
	log.SetFlags(0)
	handlePubsubMessage(msg, chanCommand)
	expectedError := "Running command: ls /nonexistent\n"
	expectedError += "Running [ls /nonexistent] resulted in error: exit status 2\n"
	result := fakeWriter.String()
	if result != expectedError {
		t.Errorf("handlePubsubMessage() failed: got\n%v instead of\n%v",
			result, expectedError)
	}
	log.SetOutput(ioutil.Discard)
}

func TestConfigPath(t *testing.T) {
	fakeArgs := []string{"foo"}
	path := configPath(fakeArgs)
	if path != "/etc/acacia.json" {
		t.Error("configPath() without args failed")
	}

	fakeArgs = []string{"foo", "bar"}
	path = configPath(fakeArgs)
	if path != "bar" {
		t.Error("configPath() with args failed")
	}
}
