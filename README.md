# Terraform provider for RavenDB 

## Supported Platforms
 
 - Linux
 - Windows

## Where to Ask for Help

If you have any questions, or need further assistance, you can [contact us directly](https://ravendb.net/contact).

## Requirements

| Name | Version |
|------|---------|
| terraform | >= 1.0.3 |

## Providers

| Name | Version |
|------|---------|
|ravendb|1.0.0

## Sample usage

### Providers
```hcl
terraform {
  required_providers {
    ravendb = {
      source  = "ravendb.net/ravendb/ravendb"
      version = "1.0.0"
    }
  }
}
    
provider "aws" {
  region = "us-east-1"
}
```
### Local variables for RavenDB server resource 

```hcl
locals {
  
  # Node tags
  nodes = toset(["a", "b", "c"])
  
  # Ec2 hosts
  hosts = flatten([
    for instance in module.ec2_instances : [
      instance.public_ip
    ]
  ])
  
  # This sample represents the nodes that will be used for insecure setup
  list = flatten([
    for instance in module.ec2_instances: [
       "http://${instance.public_ip}:8080"
    ]
  ])
  
  # This sample represents the nodes that will be used for secure setup
  list = [for tag in local.nodes : "https://${tag}.omermichleviz.development.run"]
}
```

### RavenDB server resource
```hcl
resource "ravendb_server" "server" {
  hosts              = local.hosts
  database           = "firewire"
  insecure           = true
  certificate        = filebase64("/path/to/cert.pfx")
  package {
    version = "5.2.2"
  }
  url {
    list      = local.list
    http_port = 8080
    tcp_port  = 38880
  }
  license = filebase64("/path/to/license.json")
  settings_override = {
   "Indexing.MapBatchSize": 16384
  }
  ssh {
    user = "ubuntu"
    pem  = filebase64("/path/to/server.pem")
  }
}
```
### Output 
```hcl
output "public_instance_ips" {
    value = local.list
}
output "database_name" {
    value = ravendb_server.server.database
}
```
## Inputs
| Name | Description | Type  | Required |
|------|-------------|------|--------:|
| hosts | The hostnames (or ip addresses) of the nodes that terraform will use to setup the RavenDB cluster. | `list` | yes
| database - `optional` | The database name to check whether he is alive or not. It will create the given database if it doesn't exists | `string` | no |
| certificate - `optional` | The cluster certificate file that is used by RavenDB for server side authentication. | `filebase64` | no 
| license | The license that will be used for the setup of the RavenDB cluster. | `filebase64` |yes 
| package<ul><li>version</li><li>arch - `optional`</li>| Object that represents the version and the OS RavenDB will be running on. Supported architectures are: amd64, arm64 and arm32 | `set`<ul><li>`string`</li><li>`string`</li> | yes |
| insecure | Whatever to allow to run RavenDB in unsecured mode. This is ***NOT*** recommended! | `bool` | no |
| settings_override | overriding the settings.json | `map[string][string]`| no |
| url<ul><li>list</li><li>http_url - `optional`</li><li>tcp_url - `optional`</li></ul>| object that represents the nodes | `set`<ul><li>`List(string)`</li><li>`int`</li> </li><li>`int`</li>  | yes |

## Debug mode
In order to be able to see debug log you need to define `environment variables`.


For `powershell`

```shell
$env:TF_LOG="DEBUG"
$env:TF_LOG_PATH='d:/debug_log.txt'
```

For `bash`
```shell
export TF_LOG=DEBUG
export TF_LOG_PATH=d:/debug_log.txt
```

### Environment variables information
https://www.terraform.io/docs/cli/config/environment-variables.html


## Environment variables for running acceptances tests

`powershell`
```shell
$env:TF_ACC=1
```

```bash
export TF_ACC=1
```




