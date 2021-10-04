module ravendb

go 1.16

replace github.com/ravendb/ravendb-go-client => C:\Work\ravendb-go-client

replace github.com/ravendb/terraform-provider-ravendb => C:\Work\terraform-provider-ravendb-1

require (
	github.com/gruntwork-io/terratest v0.38.1
	github.com/hashicorp/go-multierror v1.1.1
	github.com/hashicorp/terraform-plugin-sdk/v2 v2.8.0
	github.com/ravendb/ravendb-go-client v0.0.0-00010101000000-000000000000
	github.com/ravendb/terraform-provider-ravendb v0.0.0-00010101000000-000000000000
	golang.org/x/crypto v0.0.0-20210921155107-089bfa567519
)
