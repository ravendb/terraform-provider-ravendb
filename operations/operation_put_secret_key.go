package operations

import (
	"bytes"
	"encoding/json"
	"github.com/ravendb/ravendb-go-client"
	"net/http"
	"net/url"
	"strconv"
)

type OperationPutSecretKey struct {
	Name      string `json:"Name"`
	Base64Key string `json:"Base64Key"`
	Overwrite bool   `json:"Overwrite"`
}

func (operation *OperationPutSecretKey) GetCommand(conventions *ravendb.DocumentConventions) (ravendb.RavenCommand, error) {
	return &operationPutSecretKey{
		RavenCommandBase: ravendb.RavenCommandBase{
			ResponseType: ravendb.RavenCommandResponseTypeObject,
		},
		parent: operation,
	}, nil
}

type operationPutSecretKey struct {
	ravendb.RavenCommandBase
	parent *OperationPutSecretKey
}

func (o *operationPutSecretKey) CreateRequest(node *ravendb.ServerNode) (*http.Request, error) {
	base, err := url.Parse(node.URL + "/admin/secrets")
	if err != nil {
		return nil, err
	}
	params := url.Values{}
	params.Add("name", o.parent.Name)
	params.Add("overwrite", strconv.FormatBool(o.parent.Overwrite))
	base.RawQuery = params.Encode()

	keyBytes := []byte(o.parent.Base64Key)
	return http.NewRequest(http.MethodPost, base.String(), bytes.NewBuffer(keyBytes))
}

func (o *operationPutSecretKey) SetResponse(response []byte, fromCache bool) error {
	return json.Unmarshal(response, o.parent)
}
