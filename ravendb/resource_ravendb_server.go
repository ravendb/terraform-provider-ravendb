package ravendb

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/hashicorp/go-multierror"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"net/http"
	"strconv"
	"strings"
	"sync"
)

const (
	errorCreate = "error while creating RavenDB instances: %s"
	errorRead   = "error reading RavenDB configuration information: %s"
	errorDelete = "error deleting RavenDB instances: %s"
)

var packageArchitectures = map[string]string{
	"arm64": "_linux-arm64",
	"arm32": "-0_armhf.deb",
	"amd64": "-0_amd64.deb",
}

func resourceRavendbServer() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceServerCreate,
		ReadContext:   resourceServerRead,
		UpdateContext: resourceServerUpdate,
		DeleteContext: resourceServerDelete,

		Schema: map[string]*schema.Schema{
			"hosts": {
				Type:        schema.TypeList,
				Required:    true,
				Description: "The hostnames (or ip addresses) of the nodes that terraform will use to setup the RavenDB cluster.",
				Elem: &schema.Schema{
					Type:         schema.TypeString,
					ValidateFunc: validation.IsIPAddress,
				},
				MinItems: 1,
			},
			"database": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The database name to check whether he is alive or not.",
			},
			"certificate": {
				Type:         schema.TypeString,
				Optional:     true,
				Description:  "The cluster certificate file that is used by RavenDB for server side authentication.",
				ValidateFunc: validation.StringIsBase64,
			},
			"license": {
				Type:         schema.TypeString,
				Required:     true,
				Description:  "The license that will be used for the setup of the RavenDB cluster.",
				ValidateFunc: validation.StringIsBase64,
			},
			"package": {
				Type:     schema.TypeSet,
				Required: true,
				MaxItems: 1,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"version": {
							Type:        schema.TypeString,
							Required:    true,
							Description: "The RavenDB version to use for the cluster.",
						},
						"arch": {
							Type:        schema.TypeString,
							Optional:    true,
							Description: "Operating system architecture name - amd64, arm64, arm32",
						},
					},
				},
			},
			"insecure": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Whatever to allow to run RavenDB in unsecured mode. This is ***NOT*** recommended!",
			},
			"url": {
				Type:     schema.TypeSet,
				Required: true,
				MaxItems: 1,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"list": {
							Type:     schema.TypeList,
							Required: true,
							Elem: &schema.Schema{
								Type:         schema.TypeString,
								ValidateFunc: validation.IsURLWithHTTPorHTTPS,
							},
							MinItems: 1,
						},
						"http_port": {
							Type:         schema.TypeInt,
							Optional:     true,
							ValidateFunc: validation.IsPortNumber,
						},
						"tcp_port": {
							Type:         schema.TypeInt,
							Optional:     true,
							ValidateFunc: validation.IsPortNumber,
						},
					},
				},
			},
			"settings_override": {
				Type:     schema.TypeMap,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"assets": {
				Type:     schema.TypeMap,
				Optional: true,
				Elem: &schema.Schema{
					Type:         schema.TypeString,
					ValidateFunc: validation.StringIsBase64,
				},
			},
			"ssh": {
				Type:     schema.TypeSet,
				Required: true,
				MaxItems: 1,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"user": {
							Type:     schema.TypeString,
							Required: true,
						},
						"pem": {
							Type:         schema.TypeString,
							Required:     true,
							ValidateFunc: validation.StringIsBase64,
						},
					},
				},
			},
			"nodes": {
				Type:        schema.TypeList,
				Computed:    true,
				Description: "The state of all the nodes in the RavenDB cluster.",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"host": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"license": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"version": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"settings": {
							Type:     schema.TypeMap,
							Computed: true,
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
						},
						"certificate": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"http_url": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"tcp_url": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"assets": {
							Type:     schema.TypeMap,
							Computed: true,
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
						},
						"insecure": {
							Type:     schema.TypeBool,
							Computed: true,
						},
						"failed": {
							Type:     schema.TypeBool,
							Computed: true,
						},
					},
				},
			},
		},
	}
}

func resourceServerCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	sc, err := parseData(d)
	if err != nil {
		return diag.FromErr(fmt.Errorf(errorCreate, err.Error()))
	}

	id, err := sc.Deploy(true)
	if err != nil {
		return diag.FromErr(fmt.Errorf(errorCreate, err.Error()))
	}
	d.SetId(id)

	return resourceServerRead(ctx, d, meta)
}

func resourceServerDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	sc, err := parseData(d)
	if err != nil {
		return diag.FromErr(fmt.Errorf(errorDelete, err.Error()))
	}
	return sc.RemoveRavenDbInstances()
}

func convertNode(node NodeState) map[string]interface{} {
	return map[string]interface{}{
		"host":        node.Host,
		"license":     base64.StdEncoding.EncodeToString(node.Licence),
		"settings":    node.Settings,
		"certificate": base64.StdEncoding.EncodeToString(node.ClusterCertificate),
		"http_url":    node.HttpUrl,
		"tcp_url":     node.TcpUrl,
		"assets":      node.Assets,
		"insecure":    node.Insecure,
		"version":     node.Version,
		"failed":      node.Failed,
	}
}

func parseData(d *schema.ResourceData) (ServerConfig, error) {
	var sc ServerConfig

	if insecure, ok := d.GetOk("insecure"); ok {
		sc.Insecure = insecure.(bool)
	}

	hosts := d.Get("hosts").([]interface{})
	sc.Hosts = make([]string, len(hosts))
	for i, host := range hosts {
		sc.Hosts[i] = host.(string)
	}

	if dbName, ok := d.GetOk("database"); ok {
		sc.HealthcheckDatabase = dbName.(string)
	}

	certBas64 := d.Get("certificate").(string)
	cert, err := base64.StdEncoding.DecodeString(certBas64)
	if err != nil {
		return sc, err
	}
	if allZero(cert) == false {
		sc.ClusterCertificate = cert
	}

	licenseBas64 := d.Get("license").(string)
	license, err := base64.StdEncoding.DecodeString(licenseBas64)
	if err != nil {
		return sc, err
	}
	sc.License = license

	packageSet := d.Get("package").(*schema.Set).List()
	for _, v := range packageSet {
		value := v.(map[string]interface{})
		sc.Package.Version = value["version"].(string)
		sc.Package.Arch = value["arch"].(string)
		err := validatePackage(&sc)
		if err != nil {
			return sc, err
		}
	}

	assets := d.Get("assets").(map[string]interface{})
	sc.Assets = map[string][]byte{}
	for name, base64Val := range assets {
		value, err := base64.StdEncoding.DecodeString(base64Val.(string))
		if err != nil {
			return sc, err
		}
		sc.Assets[name] = value
	}
	settings := d.Get("settings_override").(map[string]interface{})
	sc.Settings = make(map[string]interface{})
	for k, v := range settings {
		sc.Settings[k] = v.(string)
	}

	sshSet := d.Get("ssh").(*schema.Set).List()
	for _, v := range sshSet {
		value := v.(map[string]interface{})
		sc.SSH.User = value["user"].(string)
		pemBase64 := value["pem"].(string)
		pem, err := base64.StdEncoding.DecodeString(pemBase64)
		if err != nil {
			return sc, err
		}
		sc.SSH.Pem = pem
	}

	urlSet := d.Get("url").(*schema.Set).List()
	for _, v := range urlSet {
		value := v.(map[string]interface{})
		list := value["list"].([]interface{})
		sc.Url.List = make([]string, len(list))
		for i, url := range list {
			sc.Url.List[i] = url.(string)
		}
		if httpPort, ok := value["http_port"]; ok {
			sc.Url.HttpPort = httpPort.(int)
		} else {
			sc.Url.HttpPort = DEFAULT_SECURE_RAVENDB_HTTP_PORT
			if sc.Insecure {
				sc.Url.HttpPort = DEFAULT_INSECURE_RAVENDB_HTTP_PORT
			}
		}

		if tcpPort, ok := value["tcp_port"]; ok {
			sc.Url.TcpPort = tcpPort.(int)
		} else {
			sc.Url.TcpPort = DEFAULT_SECURE_RAVENDB_TCP_PORT
			if sc.Insecure {
				sc.Url.TcpPort = DEFAULT_INSECURE_RAVENDB_TCP_PORT
			}
		}
	}

	if sc.ClusterCertificate != nil && sc.Insecure == true {
		return sc, fmt.Errorf("expected insecure to be ture. certificate should be added when using secure mode")
	}

	return sc, nil
}
func allZero(s []byte) bool {
	for _, v := range s {
		if v != 0 {
			return false
		}
	}
	return true
}
func validatePackage(sc *ServerConfig) error {
	arc := strings.ToLower(sc.Package.Arch)
	if val, ok := packageArchitectures[arc]; ok {
		sc.Package.Arch = val
	}
	if len(strings.TrimSpace(sc.Package.Arch)) == 0 {
		sc.Package.Arch = "-0_amd64.deb"
	}
	link := "https://daily-builds.s3.us-east-1.amazonaws.com/ravendb_" + sc.Package.Version + sc.Package.Arch
	response, err := http.Head(link)
	if err != nil {
		return errors.New("unable to download the RavenDB version: " + sc.Package.Version + ", from: " + link + " because of:" + "err")
	} else if response.StatusCode != http.StatusOK {
		return errors.New(link + " is not reachable. HTTP status code: " + strconv.Itoa(response.StatusCode) + ". Please check the input version:" + sc.Package.Version + ". Url used was:" + link)
	}
	return nil
}

func resourceServerRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	sc, err := parseData(d)
	if err != nil {
		return diag.FromErr(fmt.Errorf(errorRead, err.Error()))
	}

	nodes, err := readRavenDbInstances(sc)
	if err != nil {
		return diag.FromErr(fmt.Errorf(errorRead, err.Error()))
	}

	convertedNodes := make([]interface{}, len(nodes))
	for index, node := range nodes {
		if node.Failed == false {
			convertedNodes[index] = convertNode(node)
		}
	}

	err = d.Set("nodes", convertedNodes)
	if err != nil {
		return diag.FromErr(fmt.Errorf(errorRead, err.Error()))
	}

	return nil
}

func readRavenDbInstances(sc ServerConfig) ([]NodeState, error) {
	var wg sync.WaitGroup
	var errResults error
	errorsChanel := make(chan error, len(sc.Hosts))

	var nodeStateArray []NodeState

	for index, publicIp := range sc.Hosts {
		wg.Add(1)
		go func(copyOfPublicIp string, copyOfIndex int) {
			nodeState, err := sc.ReadServer(copyOfPublicIp, copyOfIndex)
			if err != nil {
				if strings.Contains(err.Error(), "Unable to SSH to") {
					nodeState.Failed = true
					wg.Done()
					return
				} else {
					errorsChanel <- err
				}
			}
			wg.Done()
			nodeStateArray = append(nodeStateArray, nodeState)
		}(publicIp, index)
	}

	wg.Wait()
	close(errorsChanel)

	if len(errorsChanel) > 0 {
		for err := range errorsChanel {
			errResults = multierror.Append(errResults, err)
		}
		return nil, errResults
	}

	return nodeStateArray, nil
}

func resourceServerUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	return resourceServerCreate(ctx, d, meta)
}
