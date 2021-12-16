package ravendb

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/hashicorp/go-multierror"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/ravendb/ravendb-go-client"
	"github.com/ravendb/ravendb-go-client/serverwide/certificates"
	"github.com/ravendb/ravendb-go-client/serverwide/operations"
	"golang.org/x/crypto/ssh"
	"log"
	"net"
	"net/url"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	NUMBER_OF_RETRIES                       int    = 5
	DEFAULT_SECURE_RAVENDB_HTTP_PORT        int    = 443
	DEFAULT_USECURED_RAVENDB_HTTP_PORT      int    = 8080
	DEFAULT_SECURE_RAVENDB_TCP_PORT         int    = 38888
	DEFAULT_UNSECURED_RAVENDB_TCP_PORT      int    = 38881
	DEFAULT_HTTP_PORT                       int    = 80
	CREDENTIALS_FOR_SECURE_STORE_FIELD_NAME string = "store"
	ADMIN_CERTIFICATE                       string = "Admin Certificate"
)

type ServerConfig struct {
	Package             Package
	Hosts               []string
	License             []byte
	Settings            map[string]interface{}
	ClusterSetupZip     map[string]*CertificateHolder
	Url                 Url
	Assets              map[string][]byte
	Unsecured           bool
	SSH                 SSH
	HealthcheckDatabase string
}

type CertificateHolder struct {
	Pfx  []byte `json:"pfx"`
	Cert []byte `json:"cert"`
	Key  []byte `json:"key"`
}

type NodeState struct {
	Host            string
	Licence         []byte
	Settings        map[string]interface{}
	ClusterSetupZip map[string]CertificateHolder
	HttpUrl         string
	TcpUrl          string
	Assets          map[string][]byte
	Unsecured       bool
	Version         string
	Failed          bool
}

type Package struct {
	Version string
	Arch    string
}

type Url struct {
	List     []string
	HttpPort int
	TcpPort  int
}

type SSH struct {
	User string
	Pem  []byte
	Port int
}

func (s *SSH) getPort() int {
	if s.Port != 0 {
		return s.Port
	}
	return 22
}

type DeployError struct {
	Output string
	Err    error
}

func (e *DeployError) Error() string {
	return e.Err.Error() + " with output:\n" + e.Output
}

func upload(con *ssh.Client, buf bytes.Buffer, path string, content []byte) error {
	//https://chuacw.ath.cx/development/b/chuacw/archive/2019/02/04/how-the-scp-protocol-works.aspx
	session, err := con.NewSession()
	if err != nil {
		return err
	}

	buf.WriteString("sudo scp -t " + path + "\n")

	stdin, err := session.StdinPipe()
	if err != nil {
		return err
	}
	go func() {
		defer stdin.Close()
		fmt.Fprint(stdin, "C0660 "+strconv.Itoa(len(content))+" file\n")
		stdin.Write(content)
		fmt.Fprint(stdin, "\x00")
	}()

	output, err := session.CombinedOutput("sudo scp -t " + path)
	buf.Write(output)
	if err != nil {
		return &DeployError{
			Err:    err,
			Output: buf.String(),
		}
	}

	session.Close()

	session, err = con.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()

	buf.WriteString("sudo chown ravendb:ravendb " + path + "\n")

	output, err = session.CombinedOutput("sudo chown ravendb:ravendb " + path)
	buf.Write(output)
	if err != nil {
		return errors.New("Failed to ownership: " + path + "\n" + err.Error() + "\n")
	}

	return nil
}

func (sc *ServerConfig) deployRavenDbInstances(parallel bool) error {
	var wg sync.WaitGroup
	errorsChannel := make(chan error, len(sc.Hosts))

	for index, publicIp := range sc.Hosts {
		wg.Add(1)
		deployAction := func(copyOfPublicIp string, copyOfIndex int) {
			err := sc.deployServer(copyOfPublicIp, copyOfIndex)
			if err != nil {
				errorsChannel <- err
			}
			wg.Done()
		}
		if parallel {
			go deployAction(publicIp, index)
		} else {
			deployAction(publicIp, index)
		}
	}

	wg.Wait()
	close(errorsChannel)

	var result error

	for err := range errorsChannel {
		result = multierror.Append(result, err)
	}
	return result
}

func listFiles(conn *ssh.Client, dir string) ([]string, error) {
	session, err := conn.NewSession()
	if err != nil {
		return nil, err
	}
	output, err := session.CombinedOutput("sudo find '" + dir + "' -type f  -maxdepth 1")
	if err != nil {
		return nil, errors.New(string(output))
	}
	str := string(output)
	lines := strings.Split(str, "\n")
	return lines[:len(lines)-1], nil
}

func (sc *ServerConfig) ReadServer(publicIP string, index int) (NodeState, error) {
	var stdoutBuf bytes.Buffer
	var ns NodeState
	var conn *ssh.Client
	var store *ravendb.DocumentStore
	defer func() {
		log.Println(stdoutBuf.String())
	}()

	signer, err := ssh.ParsePrivateKey(sc.SSH.Pem)
	if err != nil {
		return ns, err
	}

	authConfig := &ssh.ClientConfig{
		User:            sc.SSH.User,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         time.Second * 10,
	}

	conn, err = sc.ConnectToRemoteWithRetry(publicIP, conn, authConfig)
	if err != nil {
		return ns, err
	}

	defer conn.Close()
	files, err := listFiles(conn, "/etc/ravendb")
	if err != nil {
		return ns, err
	}
	ns.Assets = make(map[string][]byte)
	for _, file := range files {
		_, fileName := filepath.Split(file)

		contents, err := readFileContents(file, stdoutBuf, conn)
		if err != nil {
			return ns, err
		}
		if contents == nil {
			contents = make([]byte, 0) // empty file
		}
		ns.Assets[fileName] = contents
	}

	ns.Settings = make(map[string]interface{})
	if file, ok := ns.Assets["settings.json"]; ok {
		err = json.Unmarshal(file, &ns.Settings)
		if err != nil {
			stdoutBuf.WriteString("Failed to parse settings.json\n")
			stdoutBuf.Write(file)
			return ns, err
		}
		delete(ns.Assets, "settings.json")
	}
	//workaround to convert unmarshalled map[string]interface{} values to string.
	for key := range ns.Settings {
		ns.Settings[key] = fmt.Sprintf("%v", ns.Settings[key])
	}

	if license, ok := ns.Assets["license.json"]; ok {
		ns.Licence = license
		delete(ns.Assets, "license.json")
	}

	if cert, ok := ns.Assets["cluster.server.certificate.pfx"]; ok {
		var certHolder CertificateHolder
		ns.ClusterSetupZip = make(map[string]CertificateHolder)
		certHolder.Pfx = cert
		ns.ClusterSetupZip[string(index+'A')] = certHolder
		delete(ns.Assets, "cluster.server.certificate.pfx")
	}

	name := CREDENTIALS_FOR_SECURE_STORE_FIELD_NAME
	if val, ok := sc.ClusterSetupZip[name]; ok {
		store, err = getStore(sc, *val)
		if err != nil {
			return ns, err
		}
	} else {
		store, err = getStore(sc, ns.ClusterSetupZip[string(index+'A')])
		if err != nil {
			return ns, err
		}
	}

	buildNumber := operations.OperationGetBuildNumber{}
	err = executeWithRetries(store, &buildNumber)
	if err != nil {
		return ns, err
	}

	ns.Version = strconv.Itoa(buildNumber.BuildVersion)

	ns.Host = publicIP
	ns.TcpUrl = ns.Settings["PublicServerUrl"].(string)
	ns.HttpUrl = ns.Settings["PublicServerUrl.Tcp"].(string)
	if unsecuredAccessAllowed, ok := ns.Settings["Security.UnsecuredAccessAllowed"]; ok {
		ns.Unsecured = unsecuredAccessAllowed == "PublicNetwork"
	}

	delete(ns.Settings, "PublicServerUrl")
	delete(ns.Settings, "PublicServerUrl.Tcp")
	delete(ns.Settings, "Security.UnsecuredAccessAllowed")

	return ns, nil
}

func (sc *ServerConfig) deployServer(publicIP string, index int) (err error) {
	var stdoutBuf bytes.Buffer
	var conn *ssh.Client
	defer func() {
		log.Println(stdoutBuf.String())
	}()
	ravenPackageUrl := "https://daily-builds.s3.us-east-1.amazonaws.com/ravendb_" + sc.Package.Version + sc.Package.Arch

	signer, err := ssh.ParsePrivateKey(sc.SSH.Pem)
	if err != nil {
		return err
	}
	authConfig := &ssh.ClientConfig{
		User:            sc.SSH.User,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         1 * time.Minute,
	}
	conn, err = sc.ConnectToRemoteWithRetry(publicIP, conn, authConfig)
	if err != nil {
		return err
	}
	defer conn.Close()
	err = sc.execute(publicIP, []string{
		"n=0; while [ \"$n\" -lt 10 ] && [ ! -f /var/lib/cloud/instance/boot-finished ]; do echo 'Waiting for cloud-init...'; n=$(( n + 1 )); sleep 1; done",
		"wget -nv -O ravendb.deb " + ravenPackageUrl,
		"timeout 100 bash -c -- 'while ! sudo apt-get update -y; do sleep 1; done'",
		"sudo apt-get install -y -f ./ravendb.deb",
	}, "", &stdoutBuf, conn)
	if err != nil {
		return err
	}

	err = upload(conn, stdoutBuf, "/etc/ravendb/license.json", sc.License)
	if err != nil {
		return err
	}

	contents, err := readFileContents("/etc/ravendb/settings.json", stdoutBuf, conn)
	if err != nil {
		return err
	}

	var settings map[string]interface{}
	err = json.Unmarshal(contents, &settings)
	if err != nil {
		stdoutBuf.WriteString("failed to ravendb settings.json\n")
		stdoutBuf.Write(contents)
		return err
	}

	for path, content := range sc.Assets {
		splittedPath := strings.Split(path, "/")
		directories := splittedPath[1 : len(splittedPath)-1]
		absolutePath := strings.Join(directories, "/")

		err = sc.execute(publicIP, []string{
			"sudo mkdir -p /" + absolutePath,
		}, "", &stdoutBuf, conn)
		if err != nil {
			return err
		}

		err = upload(conn, stdoutBuf, path, content)
		if err != nil {
			return err
		}
	}

	if sc.ClusterSetupZip != nil && sc.Unsecured == false {
		settings["Security.Certificate.Path"] = "/etc/ravendb/cluster.server.certificate.pfx"
		err = upload(conn, stdoutBuf, "/etc/ravendb/cluster.server.certificate.pfx", sc.ClusterSetupZip[string(index+'A')].Pfx)
		if err != nil {
			return err
		}

		err = sc.execute(publicIP, []string{
			"sudo chown ravendb:ravendb /etc/ravendb/cluster.server.certificate.pfx",
		}, "sudo systemctl status ravendb", &stdoutBuf, conn)
		if err != nil {
			return err
		}
	}

	scheme := "https"
	if sc.Unsecured {
		settings["Security.UnsecuredAccessAllowed"] = "PublicNetwork"
		scheme = "http"
	}
	httpUrl, err := sc.setupUrls(index, scheme, settings)
	if err != nil {
		return err
	}

	settings["ServerUrl"] = scheme + "://0.0.0.0:" + strconv.Itoa(sc.Url.HttpPort)
	settings["ServerUrl.Tcp"] = "tcp://0.0.0.0:" + strconv.Itoa(sc.Url.TcpPort)
	settings["Setup.Mode"] = "None"
	settings["License.Path"] = "/etc/ravendb/license.json"

	for key, value := range sc.Settings {
		settings[key] = value
	}

	jsonOut, err := json.MarshalIndent(settings, "", "\t")
	if err != nil {
		return err
	}

	err = upload(conn, stdoutBuf, "/etc/ravendb/settings.json", jsonOut)
	if err != nil {
		return err
	}
	err = sc.execute(publicIP, []string{
		"sudo chown ravendb:ravendb /etc/ravendb/license.json",
		"sudo systemctl restart ravendb",
		//"timeout 100 bash -c -- 'while ! curl -vvv -k " + httpUrl + "/setup/alive; do sleep 1; done'",
		"timeout 100 bash -c -- 'while ! curl -vvv -k " + httpUrl + "/setup/alive; do echo \"Curl failed with exit code $?\"; sleep 1; done'",
	}, "sudo systemctl status ravendb", &stdoutBuf, conn)
	if err != nil {
		return err
	}

	return nil
}

func (sc *ServerConfig) ConvertPfx() (holder CertificateHolder, err error) {
	if sc.ClusterSetupZip == nil || sc.Unsecured {
		return holder, nil
	}

	var stdoutBuf bytes.Buffer
	var conn *ssh.Client
	defer func() {
		log.Println(stdoutBuf.String())
	}()

	signer, err := ssh.ParsePrivateKey(sc.SSH.Pem)
	if err != nil {
		return holder, err
	}
	authConfig := &ssh.ClientConfig{
		User:            sc.SSH.User,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         1 * time.Minute,
	}
	conn, err = sc.ConnectToRemoteWithRetry(sc.Hosts[0], conn, authConfig)
	if err != nil {
		return holder, err
	}
	defer conn.Close()

	return sc.extractServerKeyAndCertForStore(sc.Hosts[0], conn, stdoutBuf)
}

func (sc *ServerConfig) copyToRemoteGivenAbsolutePath(publicIP string, path string, stdoutBuf bytes.Buffer, conn *ssh.Client, content []byte) error {
	splittedPath := strings.Split(path, "/")
	directories := splittedPath[1 : len(splittedPath)-1]
	absolutePath := strings.Join(directories, "/")

	err := sc.execute(publicIP, []string{
		"sudo mkdir -p /" + absolutePath,
	}, "", &stdoutBuf, conn)
	if err != nil {
		return err
	}

	err = upload(conn, stdoutBuf, path, content)
	if err != nil {
		return err
	}
	return nil
}

func (sc *ServerConfig) extractServerKeyAndCertForStore(publicIP string, conn *ssh.Client, stdoutBuf bytes.Buffer) (CertificateHolder, error) {
	var certHolder CertificateHolder
	var pfx = "/etc/ravendb/cluster.server.certificate.pfx"
	var key = "/etc/ravendb/cluster.server.certificate.key"
	var crt = "/etc/ravendb/cluster.server.certificate.crt"

	err := sc.execute(publicIP, []string{
		"sudo openssl pkcs12 -in " + pfx + " -nocerts -nodes -out " + key + " -password pass:",
		"sudo openssl pkcs12 -in " + pfx + " -clcerts -nokeys -out " + crt + " -password pass:",
	}, "", &stdoutBuf, conn)
	if err != nil {
		return CertificateHolder{}, err
	}

	bytes, err := readFileContents(key, stdoutBuf, conn)
	if err != nil {
		return CertificateHolder{}, err
	}
	certHolder.Key = bytes

	bytes, err = readFileContents(crt, stdoutBuf, conn)
	if err != nil {
		return CertificateHolder{}, err
	}
	certHolder.Cert = bytes

	err = sc.execute(publicIP, []string{
		"sudo rm " + key + "\n",
		"sudo rm " + crt + "\n",
	}, "", &stdoutBuf, conn)
	if err != nil {
		return CertificateHolder{}, err
	}

	return certHolder, nil
}

func (sc *ServerConfig) ConnectToRemoteWithRetry(publicIP string, conn *ssh.Client, authConfig *ssh.ClientConfig) (*ssh.Client, error) {
	var err error
	hostAndPort := net.JoinHostPort(publicIP, fmt.Sprint(sc.SSH.getPort()))
	log.Println("Trying to SHH: " + hostAndPort)
	for i := 0; i <= NUMBER_OF_RETRIES; i++ {
		conn, err = ssh.Dial("tcp", hostAndPort, authConfig)
		if err != nil && i < NUMBER_OF_RETRIES {
			time.Sleep(time.Second * 2)
		} else if err == nil {
			log.Println("Connected to " + hostAndPort)
			break
		} else {
			log.Println("Unable to SSH to " + hostAndPort + " because " + err.Error())
			return nil, errors.New("Unable to SSH to " + hostAndPort + " because " + err.Error())
		}
	}
	return conn, nil
}

func (sc *ServerConfig) setupUrls(index int, scheme string, settings map[string]interface{}) (string, error) {
	httpUrl, tcpUrl, err := sc.GetUrlByIndex(index, scheme)
	if err != nil {
		return "", err
	}
	settings["PublicServerUrl"] = httpUrl
	settings["PublicServerUrl.Tcp"] = tcpUrl
	return httpUrl, nil
}

func (sc *ServerConfig) GetUrlByIndex(index int, scheme string) (string, string, error) {
	if sc.Url.HttpPort == 0 {
		if sc.Unsecured == false {
			sc.Url.HttpPort = DEFAULT_SECURE_RAVENDB_HTTP_PORT
		} else {
			sc.Url.HttpPort = DEFAULT_USECURED_RAVENDB_HTTP_PORT
		}
	}
	if sc.Url.TcpPort == 0 {
		if sc.Unsecured == false {
			sc.Url.HttpPort = DEFAULT_SECURE_RAVENDB_TCP_PORT
		} else {
			sc.Url.TcpPort = DEFAULT_UNSECURED_RAVENDB_TCP_PORT
		}
	}

	u, err := url.Parse(sc.Url.List[index])
	if err != nil {
		return "", "", err
	}
	host := sc.maybeAddHttpPortToHost(u.Hostname())
	httpUrl := url.URL{
		Host:   host,
		Scheme: scheme,
	}
	tcpUrl := url.URL{
		Host:   u.Hostname() + ":" + strconv.Itoa(sc.Url.TcpPort),
		Scheme: "tcp",
	}
	return httpUrl.String(), tcpUrl.String(), nil
}

func (sc *ServerConfig) maybeAddHttpPortToHost(host string) string {
	if sc.Unsecured == true && sc.Url.HttpPort != DEFAULT_HTTP_PORT || sc.Unsecured == false && sc.Url.HttpPort != DEFAULT_SECURE_RAVENDB_HTTP_PORT {
		host += ":" + strconv.Itoa(sc.Url.HttpPort)
	}
	return host
}

type debugWriter struct {
	mu        sync.Mutex
	stdoutBuf *bytes.Buffer
}

func (w *debugWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.stdoutBuf.Write(p)
	return len(p), nil
}

func (sc *ServerConfig) execute(publicIp string, commands []string, onErr string, stdoutBuf *bytes.Buffer, conn *ssh.Client) error {
	writer := debugWriter{
		stdoutBuf: stdoutBuf,
	}
	stdoutBuf.WriteString(publicIp)
	for _, cmd := range commands {
		cmdStr := "$ " + cmd + "\n"
		stdoutBuf.WriteString(cmdStr)
		writer.Write([]byte(cmdStr))
		session, err := conn.NewSession()
		if err != nil {
			return err
		}

		session.Stdout = &writer
		session.Stderr = &writer

		err = session.Run(cmd)
		if err != nil {
			log.Println(err)
			if onErr != "" {
				session.Run(cmd) // executed to write to the log
			}
			session.Close()

			return &DeployError{
				Err:    err,
				Output: stdoutBuf.String(),
			}
		}
		session.Close()
	}
	return nil
}

func (sc *ServerConfig) Deploy(parallel bool) (string, error) {
	var databaseDoesNotExistError *ravendb.DatabaseDoesNotExistError
	var certHolder CertificateHolder
	var permissions map[string]string

	err := sc.deployRavenDbInstances(parallel)
	if err != nil {
		return "", err
	}

	if sc.Unsecured == false {
		certHolder, err = sc.ConvertPfx()
		if err != nil {
			return "", err
		}
	}

	store, err := getStore(sc, certHolder)
	if err != nil {
		return "", err
	}

	err = sc.addNodesToCluster(store)
	if err != nil {
		return "", err
	}

	if sc.Unsecured == false {
		certHolder, permissions, err = sc.getDbPermissionsAndAdminCertHolder()
		if err != nil {
			return "", nil
		}

		err = putCertificateInCluster(
			store,
			ADMIN_CERTIFICATE,
			certHolder.Cert,
			certificates.ClusterAdmin.String(),
			permissions)
		if err != nil {
			return "", nil
		}
	}

	store.Close()

	store, err = getStore(sc, certHolder)
	if err != nil {
		return "", err
	}

	clusterTopology, err := sc.getClusterTopology(store)
	if err != nil {
		return "", err
	}

	err = sc.getDatabaseHealthCheck(store)
	if errors.As(err, &databaseDoesNotExistError) {
		err = sc.createDb(store)
		if err != nil {
			return "", err
		}
	} else if err != nil {
		return "", err
	}

	defer store.Close()

	return clusterTopology.Topology.TopologyID, nil
}

func (sc *ServerConfig) getDbPermissionsAndAdminCertHolder() (CertificateHolder, map[string]string, error) {
	var adminCertHolder CertificateHolder
	var permissions map[string]string
	permissions = make(map[string]string)

	name := CREDENTIALS_FOR_SECURE_STORE_FIELD_NAME
	if val, ok := sc.ClusterSetupZip[name]; ok {
		adminCertHolder = *val
	} else {
		return CertificateHolder{}, nil, errors.New("cannot retrieve admin certificate from zip file. ")
	}

	if len(strings.TrimSpace(sc.HealthcheckDatabase)) != 0 {
		permissions[sc.HealthcheckDatabase] = certificates.Admin.String()
	}

	return adminCertHolder, permissions, nil
}

func (sc *ServerConfig) getDatabaseHealthCheck(store *ravendb.DocumentStore) error {
	databaseHealthCheck := operations.OperationDatabaseHealthCheck{}
	err := executeWithRetriesMaintenanceOperations(store, &databaseHealthCheck)
	if err != nil {
		return err
	}
	return nil
}

func (sc *ServerConfig) getClusterTopology(store *ravendb.DocumentStore) (operations.OperationGetClusterTopology, error) {
	clusterTopology := operations.OperationGetClusterTopology{}
	err := executeWithRetries(store, &clusterTopology)
	if err != nil {
		return operations.OperationGetClusterTopology{}, err
	}
	return clusterTopology, nil
}

func getStore(config *ServerConfig, certificateHolder CertificateHolder) (*ravendb.DocumentStore, error) {
	var host string
	var store *ravendb.DocumentStore

	host = config.Url.List[0]
	serverNode := []string{host}

	if len(strings.TrimSpace(config.HealthcheckDatabase)) != 0 {
		store = ravendb.NewDocumentStore(serverNode, config.HealthcheckDatabase)
	} else {
		store = ravendb.NewDocumentStore(serverNode, "")
	}

	if certificateHolder.Cert != nil {
		x509KeyPair, err := tls.X509KeyPair(certificateHolder.Cert, certificateHolder.Key)
		if err != nil {
			return nil, err
		}
		x509cert, err := x509.ParseCertificate(x509KeyPair.Certificate[0])
		if err != nil {
			return nil, err
		}
		store.TrustStore = x509cert
		store.Certificate = &x509KeyPair
	}

	if err := store.Initialize(); err != nil {
		return nil, err
	}

	return store, nil
}

func (sc *ServerConfig) addNodesToCluster(store *ravendb.DocumentStore) error {
	clusterTopology, err := sc.getClusterTopology(store)
	var errAllDown *ravendb.AllTopologyNodesDownError
	if errors.As(err, &errAllDown) {
		for i := 1; i < len(sc.Url.List); i++ {
			err = addNodeToCluster(store, sc.Url.List[i])
			if err != nil {
				return err
			}
		}
	} else if err != nil {
		return err
	}

	for nodeTag, nodeUrl := range clusterTopology.Topology.AllNodes {
		if contains(sc.Url.List, nodeUrl) {
			continue
		} else {
			parse, err := url.Parse(nodeUrl)
			if err != nil {
				return err
			}
			hostName := strings.Split(parse.Host, ".")
			tag := hostName[0]
			match, err := regexp.MatchString("[A-Za-z]{1,4}", tag)
			if match == false {
				tag = nodeTag
			} else {
				tag = strings.ToUpper(tag)
			}
			err = executeWithRetries(store, &operations.RemoveClusterNode{
				Node: nodeUrl,
				Tag:  tag,
			})
			if err != nil {
				return err
			}
		}
	}

	for _, node := range sc.Url.List {
		if containsValue(clusterTopology.Topology.AllNodes, node) {
			continue
		} else {
			err = addNodeToCluster(store, node)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (sc *ServerConfig) purgeRavenDbInstance(publicIP string) error {
	var stdoutBuf bytes.Buffer
	signer, err := ssh.ParsePrivateKey(sc.SSH.Pem)
	if err != nil {
		return err
	}

	authConfig := &ssh.ClientConfig{
		User:            sc.SSH.User,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	conn, err := ssh.Dial("tcp", net.JoinHostPort(publicIP, fmt.Sprint(sc.SSH.getPort())), authConfig)
	if err != nil {
		return err
	}
	defer conn.Close()

	err = sc.execute(publicIP, []string{
		"sudo apt-get -y purge ravendb",
	}, "", &stdoutBuf, conn)

	if err != nil {
		stdoutBuf.WriteString("Failed to delete ravendb instance. Host machine ip: " + publicIP + "\n")
	} else {
		stdoutBuf.WriteString("Deleted successfully ravendb instance. Host machine ip " + publicIP + "\n")

	}
	log.Println(stdoutBuf.String())
	return err
}

func (sc *ServerConfig) RemoveRavenDbInstances() diag.Diagnostics {
	var wg sync.WaitGroup
	errorsChanel := make(chan error, len(sc.Hosts))

	for index, publicIp := range sc.Hosts {
		wg.Add(1)
		go func(copyOfIndex int, copyOfPublicIp string) {
			err := sc.purgeRavenDbInstance(copyOfPublicIp)
			if err != nil {
				errorsChanel <- err
			}
			wg.Done()
		}(index, publicIp)
	}

	wg.Wait()
	close(errorsChanel)

	var result error

	for err := range errorsChanel {
		result = multierror.Append(result, err)
	}
	if result != nil {
		return diag.FromErr(fmt.Errorf(errorDelete, result.Error()))
	} else {
		return nil
	}

}

func (sc *ServerConfig) createDb(store *ravendb.DocumentStore) error {
	for i := 0; i < NUMBER_OF_RETRIES; i++ {
		topology, err := sc.getClusterTopology(store)
		if err != nil {
			return err
		}
		if len(topology.Topology.Members) != len(sc.Url.List) {
			time.Sleep(time.Second * 5)
		} else {
			break
		}
	}
	err := executeWithRetries(store,
		ravendb.NewCreateDatabaseOperation(&ravendb.DatabaseRecord{
			DatabaseName: sc.HealthcheckDatabase,
		}, len(sc.Hosts)))

	if err != nil && reflect.TypeOf(err) != reflect.TypeOf(&ravendb.ConcurrencyError{}) {
		return err
	}
	return nil
}

func putCertificateInCluster(store *ravendb.DocumentStore, certificateName string, certificateBytes []byte, securityClearance string, permissions map[string]string) error {
	return executeWithRetries(store, &certificates.OperationPutCertificate{
		CertName:          certificateName,
		CertBytes:         certificateBytes,
		SecurityClearance: securityClearance,
		Permissions:       permissions,
	})
}

func addNodeToCluster(store *ravendb.DocumentStore, node string) error {
	parse, err := url.Parse(node)
	if err != nil {
		return err
	}
	hostName := strings.Split(parse.Host, ".")
	tag := hostName[0]
	match, err := regexp.MatchString("[A-Za-z]{1,4}", tag)
	if err != nil {
		return err
	}
	if !match {
		tag = ""
	} else {
		tag = strings.ToUpper(tag)
	}
	return executeWithRetries(store, &operations.OperationAddClusterNode{
		Url: node,
		Tag: tag,
	})

}

func executeWithRetriesMaintenanceOperations(store *ravendb.DocumentStore, operation ravendb.IVoidMaintenanceOperation) error {
	var err error
	for i := 0; i < NUMBER_OF_RETRIES; i++ {
		err = store.Maintenance().Send(operation)
		if err == nil {
			return nil
		}
		// we may need to wait a bit because adding a node to the cluster may move things around
		time.Sleep(time.Second * 5)
	}
	return err
}

func executeWithRetries(store *ravendb.DocumentStore, operation ravendb.IServerOperation) error {
	var errNoLeader *ravendb.NoLeaderError
	var err error
	for i := 0; i < NUMBER_OF_RETRIES; i++ {
		err = store.Maintenance().Server().Send(operation)
		if err == nil {
			return nil
		}

		if !errors.As(err, &errNoLeader) && !errors.As(err, &errNoLeader) {
			return err
		}
		// we may need to wait a bit because adding a node to the cluster may move things around
		time.Sleep(time.Second * 5)
	}
	return err
}

func readFileContents(path string, stdoutBuf bytes.Buffer, conn *ssh.Client) ([]byte, error) {
	session, err := conn.NewSession()
	if err != nil {
		return nil, err
	}
	defer session.Close()
	stdoutBuf.WriteString("sudo cat " + path + "\n")
	out, err := session.CombinedOutput("sudo cat " + path)
	if err != nil {
		stdoutBuf.Write(out)
		return nil, &DeployError{
			Err:    err,
			Output: stdoutBuf.String(),
		}
	}
	return out, nil
}

func contains(s []string, str string) bool {
	for _, v := range s {
		if strings.ToLower(v) == str {
			return true
		}
	}
	return false
}

func containsValue(m map[string]string, v string) bool {
	for _, x := range m {
		if x == v {
			return true
		}
	}
	return false
}
