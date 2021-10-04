package operations

import (
	"github.com/ravendb/ravendb-go-client"
	"net/http"
)

type OperationSetupAlive struct {
}

func (o *OperationSetupAlive) GetCommand(conventions *ravendb.DocumentConventions) (ravendb.RavenCommand, error) {
	return &setupAliveCommand{
		RavenCommandBase: ravendb.RavenCommandBase{
			ResponseType: ravendb.RavenCommandResponseTypeEmpty,
		},
	}, nil
}

type setupAliveCommand struct {
	ravendb.RavenCommandBase
}

func (c *setupAliveCommand) CreateRequest(node *ravendb.ServerNode) (*http.Request, error) {
	url := node.URL + "/setup/alive"
	return ravendb.NewHttpPost(url, []byte{})
}

func (c *setupAliveCommand) SetResponse(response []byte, fromCache bool) error {
	return nil
}