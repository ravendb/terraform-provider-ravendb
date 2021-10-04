package ravendb

import (
	"context"
	"encoding/base64"
	"fmt"
	"github.com/hashicorp/go-multierror"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"net/http"
	"sync"
)

const (
	errorCreate = "error while creating information: %s"
	errorRead   = "error getting raven configuration information: %s"
	errorDelete = "error deleting RavenDbInstances: %s"
)

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
			"healthcheck_database": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The database name to check whether he is alive or not.",
			},
			"certificate_base64": {
				Type:         schema.TypeString,
				Optional:     true,
				Description:  "The cluster certificate file that is used by RavenDB for server side authentication.",
			},
			"license": {
				Type:         schema.TypeString,
				Required:     true,
				Description:  "The license that will be used for the setup of the RavenDB cluster.",
				ValidateFunc: validation.StringIsBase64,
			},
			"version": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The RavenDB version to use for the cluster.",
				ValidateFunc: func(val interface{}, key string) (warns []string, errs []error) {
					v, ok := val.(string)
					if !ok {
						errs = append(errs, fmt.Errorf("expected type of %q to be string", v))
						return warns, errs
					}
					link := "https://daily-builds.s3.us-east-1.amazonaws.com/ravendb_" + v + "-0_amd64.deb"
					response, err := http.Head(link)
					if err != nil {
						errs = append(errs, fmt.Errorf("unable to download the RavenDB version: %s, from: %s because of: %s", v, link, err.Error()))
						return warns, errs
					} else if response.StatusCode != http.StatusOK {
						errs = append(errs, fmt.Errorf("'%s' is not reachable. HTTP status code: %d. Please check the input version: %s. Url used was: %s", link, response.StatusCode, v, link))
						return warns, errs
					}
					return warns, errs
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
			"settings": {
				Type:     schema.TypeMap,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"files": {
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
						"pem_base64": {
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
						"certificate_base64": {
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
						"files": {
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

func convertNode(node NodeState) interface{} {
	return map[string]interface{}{
		"host":               node.Host,
		"license":            base64.StdEncoding.EncodeToString(node.Licence),
		"settings":           node.Settings,
		"certificate_base64": base64.StdEncoding.EncodeToString(node.ClusterCertificate),
		"http_url":           node.HttpUrl,
		"tcp_url":            node.TcpUrl,
		"files":              node.Files,
		"insecure":           node.Insecure,
		"version":            node.Version,
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

	if dbName, ok := d.GetOk("healthcheck_database"); ok {
		sc.HealthcheckDatabase = dbName.(string)
	}

	certBas64 := d.Get("certificate_base64").(string)
	cert, err := base64.StdEncoding.DecodeString(certBas64)
	if err != nil {
		return sc, err
	}
	sc.ClusterCertificate = cert

	licenseBas64 := d.Get("license").(string)
	license, err := base64.StdEncoding.DecodeString(licenseBas64)
	if err != nil {
		return sc, err
	}
	sc.License = license

	version := d.Get("version").(string)
	if err != nil {
		return sc, err
	}
	sc.Version = version

	files := d.Get("files").(map[string]interface{})
	sc.Files = map[string][]byte{}
	for name, base64Val := range files {
		value, err := base64.StdEncoding.DecodeString(base64Val.(string))
		if err != nil {
			return sc, err
		}
		sc.Files[name] = value
	}
	settings := d.Get("settings").(map[string]interface{})
	sc.Settings = make(map[string]interface{})
	for k, v := range settings {
		sc.Settings[k] = v.(string)
	}

	sshSet := d.Get("ssh").(*schema.Set).List()
	for _, v := range sshSet {
		value := v.(map[string]interface{})
		sc.SSH.User = value["user"].(string)
		pemBase64 := value["pem_base64"].(string)
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
		if http, ok := value["http_port"]; ok {
			sc.Url.HttpPort = http.(int)
		} else {
			sc.Url.HttpPort = 443
			if sc.Insecure {
				sc.Url.HttpPort = 8080
			}
		}

		if tcp, ok := value["tcp_port"]; ok {
			sc.Url.TcpPort = tcp.(int)
		} else {
			sc.Url.TcpPort = 38880
			if sc.Insecure {
				sc.Url.TcpPort = 38881
			}
		}
	}

	if sc.ClusterCertificate != nil && sc.Insecure == true{
		return sc, fmt.Errorf("expected insecure to be false. certificate should be added only on secure mode")
	}

	return sc, nil
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

	for i, node := range nodes {
		convertedNodes[i] = convertNode(node)
	}
	d.Set("nodes", convertedNodes)

	return nil
}

func readRavenDbInstances(sc ServerConfig) ([]NodeState, error) {
	var wg sync.WaitGroup
	var errResults error
	errorsChanel := make(chan error, len(sc.Hosts))
	nodeStateArray := make([]NodeState, len(sc.Hosts))

	for index, publicIp := range sc.Hosts {
		wg.Add(1)
		go func(copyOfPublicIp string, copyOfIndex int) {
			nodeState, err := sc.ReadServer(copyOfPublicIp, copyOfIndex)
			if err != nil {
				errorsChanel <- err
			}
			wg.Done()
			nodeStateArray[copyOfIndex] = nodeState
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
