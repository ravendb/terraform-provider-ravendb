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
	"github.com/ravendb/ravendb-go-client/serverwide/operations"
	"github.com/ravendb/terraform-provider-ravendb/utils"
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
	//test_operations "ravendb/ravendb/operations"
)

const numberOfIterationsToDial int = 20
const numberOfIterationsToTryAndGetTopology int = 5
const numberOfIterationsExecuteWithRetries int = 3

type ServerConfig struct {
	Version             string
	Hosts               []string
	License             []byte
	Settings            map[string]interface{}
	ClusterCertificate  []byte
	Url                 Url
	Files               map[string][]byte
	Insecure            bool
	SSH                 SSH
	HealthcheckDatabase string
}

type NodeState struct {
	Host               string
	Licence            []byte
	Settings           map[string]interface{}
	ClusterCertificate []byte
	HttpUrl            string
	TcpUrl             string
	Files              map[string][]byte
	Insecure           bool
	Version            int
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
	session, err := con.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()

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

	return nil
}

func (sc *ServerConfig) deployRavenDbInstances(parallel bool) error {
	var wg sync.WaitGroup
	errorsChanel := make(chan error, len(sc.Hosts))

	for index, publicIp := range sc.Hosts {
		wg.Add(1)
		deployAction := func(copyOfPublicIp string, copyOfIndex int) {
			err := sc.deployServer(copyOfPublicIp, copyOfIndex)
			if err != nil {
				errorsChanel <- err
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
	close(errorsChanel)

	var result error

	for err := range errorsChanel {
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

	signer, err := ssh.ParsePrivateKey(sc.SSH.Pem)
	if err != nil {
		return ns, err
	}

	authConfig := &ssh.ClientConfig{
		User:            sc.SSH.User,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	conn, err := ssh.Dial("tcp", net.JoinHostPort(publicIP, fmt.Sprint(sc.SSH.getPort())), authConfig)
	if err != nil {
		return ns, err
	}
	defer conn.Close()

	files, err := listFiles(conn, "/etc/ravendb")
	if err != nil {
		return ns, err
	}
	ns.Files = make(map[string][]byte)
	for _, file := range files {
		_, fileName := filepath.Split(file)

		contents, err := readFileContents(file, stdoutBuf, conn)
		if err != nil {
			return ns, err
		}
		if contents == nil {
			contents = make([]byte, 0) // empty file
		}
		ns.Files[fileName] = contents
	}

	ns.Settings = make(map[string]interface{})
	if file, ok := ns.Files["settings.json"]; ok {
		err = json.Unmarshal(file, &ns.Settings)
		if err != nil {
			stdoutBuf.WriteString("Failed to url JSON\n")
			stdoutBuf.Write(file)
			return ns, err
		}
		delete(ns.Files, "settings.json")
	}

	if license, ok := ns.Files["license.json"]; ok {
		ns.Licence = license
		delete(ns.Files, "license.json")
	}
	if cert, ok := ns.Files["certificate.pfx"]; ok {
		ns.ClusterCertificate = cert
		delete(ns.Files, "certificate.pfx")
	}

	store, err := getStore(sc, index)
	if err != nil {
		return ns, err
	}
	buildNumber := operations.OperationGetBuildNumber{}
	err = executeWithRetries(store, &buildNumber)
	if err != nil {
		return ns, err
	}

	ns.Version = buildNumber.BuildVersion

	ns.Host = publicIP
	ns.TcpUrl = ns.Settings["PublicServerUrl"].(string)
	ns.HttpUrl = ns.Settings["PublicServerUrl.Tcp"].(string)
	if unsecuredAccessAllowed, ok := ns.Settings["Security.UnsecuredAccessAllowed"]; ok {
		ns.Insecure = unsecuredAccessAllowed.(string) == "PublicNetwork"
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
	ravenPackageUrl := "https://daily-builds.s3.us-east-1.amazonaws.com/ravendb_" + sc.Version + "-0_amd64.deb"

	signer, err := ssh.ParsePrivateKey(sc.SSH.Pem)
	if err != nil {
		return err
	}
	authConfig := &ssh.ClientConfig{
		User:            sc.SSH.User,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         time.Minute * 10,
	}
	for i := 0; i < numberOfIterationsToDial; i++ {
		conn, err = ssh.Dial("tcp", net.JoinHostPort(publicIP, fmt.Sprint(sc.SSH.getPort())), authConfig)
		if err == nil {
			break
		} else {
			if i != numberOfIterationsToDial {
				time.Sleep(time.Second * 5)
			} else {
				return err
			}
		}
	}

	defer conn.Close()
	for i := 0; i < numberOfIterationsToDial; i++ {
		err = sc.execute(publicIP, []string{
			"n=0; while [ \"$n\" -lt 10 ] && [ ! -f /var/lib/cloud/instance/boot-finished ]; do echo 'Waiting for cloud-init...'; n=$(( n + 1 )); sleep 1; done",
			"wget -nv -O ravendb.deb " + ravenPackageUrl,
			"sudo apt-get update -y",
			"sudo apt-get install -y -f ./ravendb.deb",
		}, stdoutBuf, conn)
		if err == nil {
			break
		} else {
			if i != numberOfIterationsToDial {
				time.Sleep(time.Second)
			} else {
				return err
			}
		}
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
		stdoutBuf.WriteString("Failed to parse JSON\n")
		stdoutBuf.Write(contents)
		return err
	}

	if sc.ClusterCertificate != nil && sc.Insecure == false {
		settings["Security.Certificate.Path"] = "/etc/ravendb/certificate.pfx"
		err = upload(conn, stdoutBuf, "/etc/ravendb/certificate.pfx", sc.ClusterCertificate)
		if err != nil {
			return err
		}
	}

	scheme := "https"
	if sc.Insecure {
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
		"sudo chown -R ravendb:ravendb /etc/ravendb/",
		"sudo systemctl restart ravendb",
		"curl -v --retry-connrefused --retry 100 --retry-delay 1 " + httpUrl + "/setup/alive",
	}, stdoutBuf, conn)
	if err != nil {
		return err
	}

	return nil
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
		if sc.Insecure == false {
			sc.Url.HttpPort = 443
		} else {
			sc.Url.HttpPort = 8080
		}
	}
	if sc.Url.TcpPort == 0 {
		sc.Url.TcpPort = 38880
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
	if sc.Insecure == true && sc.Url.HttpPort != 80 || sc.Insecure == false && sc.Url.HttpPort != 443 {
		host += ":" + strconv.Itoa(sc.Url.HttpPort)
	}
	return host
}

type debugWriter struct {
	mu        sync.Mutex
	publicIp  string
	stdoutBuf bytes.Buffer
}

func (w *debugWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	log.Println(w.publicIp + " > " + string(p))
	w.stdoutBuf.Write(p)
	return len(p), nil
}

func (sc *ServerConfig) execute(publicIp string, commands []string, stdoutBuf bytes.Buffer, conn *ssh.Client) error {
	writer := debugWriter{
		publicIp:  publicIp,
		stdoutBuf: stdoutBuf,
	}
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
		session.Close()
		if err != nil {
			return &DeployError{
				Err:    err,
				Output: stdoutBuf.String(),
			}
		}
	}
	return nil
}

func (sc *ServerConfig) Deploy(parallel bool) (string, error) {
	store, err := getStore(sc, 0)
	if err != nil {
		return "", err
	}

	err = sc.deployRavenDbInstances(parallel)
	if err != nil {
		return "", err
	}

	err = sc.addNodesToCluster(store)
	if err != nil {
		return "", err
	}

	clusterTopology, err := sc.getClusterTopology(store)
	if err != nil {
		return "", err
	}

	err = sc.createDb(store)
	if err != nil {
		return "", err
	}

	return clusterTopology.Topology.TopologyId, nil
}

func (sc *ServerConfig) getSetupAlive(node string, store *ravendb.DocumentStore) error {
	setupAlive := operations.OperationSetupAlive{}
	err := store.Maintenance().Server().Send(&setupAlive) //TODO: Use the node here, missing ForNode() method
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

func getStore(config *ServerConfig, index int) (*ravendb.DocumentStore, error) {
	var host string

	host = config.Url.List[index]

	serverNode := []string{host}

	key, crt, err := utils.PfxToPem(config.ClusterCertificate)

	if err != nil {
		return nil, err
	}

	cert, err := tls.X509KeyPair(crt, key)
	if err != nil {
		return nil, err
	}

	store := ravendb.NewDocumentStore(serverNode, "")
	if err != nil {
		return nil, err
	}

	store.Certificate = &cert

	x509cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, err
	}
	store.TrustStore = x509cert
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

	for _, nodeUrl := range clusterTopology.Topology.AllNodes {
		if contains(sc.Url.List, nodeUrl) {
			continue
		} else {
			parse, err := url.Parse(nodeUrl)
			if err != nil {
				return err
			}
			hostName := strings.Split(parse.Host, ".")
			tag := strings.ToUpper(hostName[0])
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
	}, stdoutBuf, conn)

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
	for i := 0; i < numberOfIterationsToTryAndGetTopology; i++ {
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
	for i := 0; i < numberOfIterationsExecuteWithRetries; i++ {
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
	for i := 0; i < numberOfIterationsExecuteWithRetries; i++ {
		err = store.Maintenance().Server().Send(operation)
		if err == nil {
			return nil
		}
		if !errors.As(err, &errNoLeader) {
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
		if v == str {
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
