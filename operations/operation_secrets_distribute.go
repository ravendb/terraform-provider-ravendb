package operations

import (
	"bytes"
	"encoding/json"
	"github.com/ravendb/ravendb-go-client"
	"net/http"
)

type OperationDistributeSecretKey struct {
	Name string `json:"Name"`
	Node string `json:"Node"`
	Key  string `json:"Key"`
}

func (operation *OperationDistributeSecretKey) GetCommand(conventions *ravendb.DocumentConventions) (ravendb.RavenCommand, error) {
	return &operationDistributeSecretKey{
		RavenCommandBase: ravendb.RavenCommandBase{
			ResponseType: ravendb.RavenCommandResponseTypeObject,
		},
		parent: operation,
	}, nil
}

type operationDistributeSecretKey struct {
	ravendb.RavenCommandBase
	parent *OperationDistributeSecretKey
}

func (o *operationDistributeSecretKey) CreateRequest(node *ravendb.ServerNode) (*http.Request, error) {
	url := node.URL + "/admin/secrets/distribute?" + o.parent.Name + "&" + o.parent.Node
	keyBytes := []byte(o.parent.Key)
	return http.NewRequest(http.MethodPost, url, bytes.NewBuffer(keyBytes))
}

func (o *operationDistributeSecretKey) SetResponse(response []byte, fromCache bool) error {
	return json.Unmarshal(response, o.parent)
}
