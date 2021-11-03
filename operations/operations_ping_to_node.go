package operations

import (
"encoding/json"
"github.com/ravendb/ravendb-go-client"
"net/http"
)

type OperationPingToNode struct {
	Result []Result `json:"Result"`
}

type Result struct {
	URL         string   `json:"Url"`
	TCPInfoTime int      `json:"TcpInfoTime"`
	SendTime    int      `json:"SendTime"`
	ReceiveTime int      `json:"ReceiveTime"`
	Error       string   `json:"Error"`
}

func (operation *OperationPingToNode) GetCommand(conventions *ravendb.DocumentConventions) (ravendb.RavenCommand, error) {
	return &getPingNode{
		RavenCommandBase: ravendb.RavenCommandBase{
			ResponseType: ravendb.RavenCommandResponseTypeObject,
		},
		parent: operation,
	}, nil
}

type getPingNode struct {
	ravendb.RavenCommandBase
	parent *OperationPingToNode
}

func (c *getPingNode) CreateRequest(node *ravendb.ServerNode) (*http.Request, error) {
	url := node.URL + "/admin/debug/node/ping"
	return http.NewRequest(http.MethodGet, url, nil)
}

func (c *getPingNode) SetResponse(response []byte, fromCache bool) error {
	return json.Unmarshal(response, c.parent)
}