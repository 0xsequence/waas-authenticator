// Server
//go:generate go run github.com/webrpc/webrpc/cmd/webrpc-gen -schema=authenticator.ridl -target=golang -pkg=proto -server -client -out=./authenticator.gen.go

// Clients
//go:generate go run github.com/webrpc/webrpc/cmd/webrpc-gen -schema=authenticator.ridl -target=golang -pkg=proto -client -out=./clients/authenticator.gen.go
//go:generate go run github.com/webrpc/webrpc/cmd/webrpc-gen -schema=authenticator.ridl -target=typescript -client -out=./clients/authenticator.gen.ts

package proto
