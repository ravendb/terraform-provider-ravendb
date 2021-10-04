# Terraform provider for RavenDB 

## Supported Platforms
 
 - Linux

## Installing the provider

```
terraform {
  required_providers {
    ravendb = {
      source  = "ravendb.net/ravendb/ravendb"
      version = "1.0.0"
    }
  }
}
```

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
locals {
  nodes = toset(["a", "b", "c"])
}

module "ec2_instances" {
  source  = "terraform-aws-modules/ec2-instance/aws"
  version = "~> 3.0"

  for_each = local.nodes

  name = "${each.key}.ravendb"

  ami                         = "ami-09e67e426f25ce0d7"
  instance_type               = "t2.micro"
  key_name                    = "omer-tf"
  monitoring                  = false
  vpc_security_group_ids      = ["sg-03525214aee516d50"]
  subnet_id                   = "subnet-0ee70783a7dd19aa5"
  associate_public_ip_address = true
}

resource "ravendb_server" "server" {
  hosts = flatten([
    for instance in module.ec2_instances : [
      instance.public_ip
    ]
  ])

  healthcheck_database = "firewire"
  insecure             = true
  certificate_base64   = filebase64("C:\\Users\\omer\\Desktop\\cluster.server.certificate.omermichleviz.pfx")
  version              = "5.2.2"
  url {
    list = flatten([
      # for node in local.nodes: [
      #   "https://${node}.omermichleviz.development.run"
      # ]
    
      for instance in module.ec2_instances : [
        "http://${instance.public_ip}:8080"
      ]
    ])
    http_port = 8080
    tcp_port  = 38880
  }
  license = filebase64("license.json")
  settings = {
    "Raven.Testing" = "foo0o"
  }
  files = {
    "someFile" = filebase64("omer-tf.pem")
  }
  ssh {
    user       = "ubuntu"
    pem_base64 = filebase64("omer-tf.pem")
  }
}
```



## Debug mode
In order to be able to see debug log you need to define `environment variables`.

open `powershell` and enter the next commands

For running the acceptances tests run
```shell
$export:TF_ACC=1
````

`$env:TF_LOG="DEBUG"`

`$env:TF_LOG_PATH="d:/debug_log.txt"` 

refer to https://www.terraform.io/docs/cli/config/environment-variables.html for more information 

## OpenSSL

In order to connect to the machines we are using external C language libraries.
Therefore, there's a need to install `OpenSSL` on our machine

Link  - https://slproweb.com/products/Win32OpenSSL.html
Version - `Win64 OpenSSL v1.1.1L`
The installation folder will need to be inside `C:\Program Files\OpenSSl-Win64`

The only step remained is to set the `environment variables`.
`set OpenSSLDir=C:\Program Files\OpenSSL-Win64\include`

## Inputs

| Name | Description | Type  | Required |
|------|-------------|------|--------:|
| hosts | The hostnames (or ip addresses) of the nodes that terraform will use to setup the RavenDB cluster. | `list` | yes
| healthcheck_database | The database name to check whether he is alive or not. | `string` | no |
| certificate_base64 | The cluster certificate file that is used by RavenDB for server side authentication. | `filebase64` | no 
| license | The license that will be used for the setup of the RavenDB cluster. | `filebase64` |yes 
| version | The RavenDB version to use for the cluster. | `string` | yes |
| insecure | Whatever to allow to run RavenDB in unsecured mode. This is ***NOT*** recommended! | `bool` | no |
| url<ul><li>list</li><li>http_url</li><li>tcp_url</li></ul>| object that represents the nodes | `set` | yes |

## DNS Management

Add the nodes to the domain
Enter the license within <https://customers.ravendb.net>


