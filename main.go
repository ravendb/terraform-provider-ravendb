package main

import (
	"context"
	"flag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/plugin"
	"github.com/ravendb/terraform-provider-ravendb/ravendb"
	_ "io/ioutil"
	"log"
)

func main() {
	var debugMode bool

	flag.BoolVar(&debugMode, "debug", true, "set to true to run the provider with support for debuggers like delve")
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
