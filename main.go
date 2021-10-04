package main

import (
	"context"
	"flag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/plugin"
	_ "io/ioutil"
	"log"
	"ravendb/ravendb"
)

//
//func main() {
//	pem, err := ioutil.ReadFile("D:\\tf\\omer-tf.pem")
//	if err != nil {
//		log.Fatal("Cannot read pem file.")
//		log.Fatal(err)
//		return
//	}
//
//	license, err := ioutil.ReadFile("C:\\Users\\omer\\Desktop\\license.json")
//	if err != nil {
//		log.Fatal("Cannot read license file.")
//		log.Fatal(err)
//		return
//	}
//
//	cert, err := ioutil.ReadFile("C:\\Users\\omer\\Desktop\\cluster.server.certificate.omermichleviz.pfx")
//	if err != nil {
//		log.Fatal("Cannot read certificate file.")
//		log.Fatal(err)
//		return
//	}
//
//	server := ravendb.ServerConfig{
//		Hosts: []string{
//			"34.234.71.42",
//			"54.196.222.111",
//			"54.82.100.128",
//			//"54.152.67.193",
//			////"52.90.5.94",
//			//"34.238.116.205",
//		},
//		HealthcheckDatabase: "firewire",
//		Insecure:            true,
//		SSH: ravendb.SSH{
//			User: "ubuntu",
//			Pem:  pem,
//		},
//		Version:            "5.2.2",
//		ClusterCertificate: cert,
//		License:            license,
//		Url: ravendb.Url{
//			Template: "",
//			List: []string{
//				"http://34.234.71.42:8080",
//				"http://54.196.222.111:8080",
//				"http:/54.82.100.128:8080",
//				//"http://3.88.196.188:8080",
//				//"http://52.91.89.180:8080",
//				//"http://3.92.177.193:8080",
//				//"https://d.omermichleviz.development.run",
//				//"https://e.omermichleviz.development.run",
//				//"https://oren.omermichleviz.development.run",
//			},
//			HttpPort: 8080,
//			TcpPort:  38880,
//		},
//	}
//
//	log.Println("Starting deploy...")
//
//	instances := server.RemoveRavenDbInstances()
//	if instances != nil {
//		log.Fatal(instances)
//	}
//
//	//for i, host := range server.Hosts {
//	// readServer, err := server.ReadServer(host, i)
//	// if err != nil {
//	//    log.Fatal(err)
//	// }
//	// _ = readServer
//	//
//	//}
//	return
//
//}

func main() {
	var debugMode bool

	flag.BoolVar(&debugMode, "debug", false, "set to true to run the provider with support for debuggers like delve")
	flag.Parse()

	opts := &plugin.ServeOpts{
		ProviderFunc: ravendb.Provider,
	}

	if debugMode {
		err := plugin.Debug(context.Background(), "ravendb.net/ravendb/ravendb", opts)

		if err != nil {
			log.Fatal(err.Error())
		}

		return
	}

	plugin.Serve(opts)
}

