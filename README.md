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

#### Example getting RavenDB server parameters from EC2 instances Terraform resources
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
  
  # This sample represents the nodes that will be used for unsecured setup.
  ravendb_nodes_urls = flatten([
    for instance in module.ec2_instances: [
       "http://${instance.public_ip}:8080"
    ]
  ])
  
  # This samples represents the nodes that will be used for secure setup.
  ravendb_nodes_urls = [for tag in local.nodes : "https://${tag}.omermichleviz.development.run"]
    
}
```
#### RavenDB server Terraform resource parameters

```hcl
locals {
  
  # IP addresses for hosts to deploy RavenDB to
  hosts = [
         "3.95.238.149", 
         "3.87.248.150", 
         "3.95.220.189" 
         ]
  
  # This sample represents the nodes that will be used for unsecured setup.
  ravendb_nodes_urls = [
         "http://3.95.238.149:8080", 
         "http://3.87.248.150:8080", 
         "http://3.95.220.189:8080"
         ]
  
  # This samples represents the nodes that will be used for secure setup.
  ravendb_nodes_urls = [
         "https://a.domain.development.run", 
         "https://b.domain.development.run", 
         "https://c.domain.development.run" 
         ]
}
```


### RavenDB server resource
```hcl
resource "ravendb_server" "server" {
  hosts              = local.hosts
  database           = "firewire"
  unsecured          = true
  certificate        = filebase64("/path/to/cert.pfx")
  package {
    version = "5.2.2"
  }
  url {
    list      = local.ravendb_nodes_urls
    http_port = 8080
    tcp_port  = 38880
  }
  license = filebase64("/path/to/license.json")
  settings_override = {
   "Indexing.MapBatchSize": 16384
  }
  assets = {
   "/path/to/file/file_name.extension" = filebase64("/path/to/file_name.extension")
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
| hosts | The ip addresses of the nodes that terraform will use to setup the RavenDB cluster. | `list` | yes
| database - `optional` | The database name to check whether he is alive or not. It will create the given database if it doesn't exists | `string` | no |
| certificate - `optional` | The cluster certificate file that is used by RavenDB for server side authentication. | `filebase64` | no 
| license | The license file that will be used for the setup of the RavenDB cluster. | `filebase64` |yes 
| package<ul><li>version</li><li>arch - `optional`</li>| Object that represents the version and the OS RavenDB will be running on. Supported architectures are: amd64, arm64 and arm32 | `set`<ul><li>`string`</li><li>`string`</li> | yes |
| unsecured | Whatever to allow to run RavenDB in unsecured mode. This is ***NOT*** recommended! | `bool` | no |
| settings_override | overriding the settings.json. | `map[string][string]`| no |
| assets | Upload files given an absolute path. | `map[string][string]`| no |
| url<ul><li>list</li><li>http_url - `optional`</li><li>tcp_url - `optional`</li></ul>| object that represents the nodes. | `set`<ul><li>`List(string)`</li><li>`int`</li> </li><li>`int`</li>  | yes |

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




