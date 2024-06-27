package main

import (
	"net/http"

	"github.com/0xsequence/waas-authenticator/proto/builder"
)

func main() {
	svc := builder.NewBuilderServer(builder.NewMock())
	http.ListenAndServe(":9999", svc)
}
