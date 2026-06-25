module github.com/solo-io/cedar-extauthz-demo/cedar-authz-server

go 1.23.0

// The ext_authz Authorization/Check gRPC stubs come from go-control-plane; agentgateway speaks
// this standard external-authorization contract and calls this service for the decision.
require (
	github.com/cedar-policy/cedar-go v1.8.0
	github.com/envoyproxy/go-control-plane/envoy v1.32.4
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250115164207-1a7da9e5054f
	google.golang.org/grpc v1.70.0
	google.golang.org/protobuf v1.36.4 // indirect
)

require (
	github.com/cncf/xds/go v0.0.0-20240905190251-b4127c9b8d78 // indirect
	github.com/envoyproxy/protoc-gen-validate v1.2.1 // indirect
	github.com/planetscale/vtprotobuf v0.6.1-0.20240319094008-0393e58bdf10 // indirect
	golang.org/x/exp v0.0.0-20220921023135-46d9e7742f1e // indirect
	golang.org/x/net v0.34.0 // indirect
	golang.org/x/sys v0.29.0 // indirect
	golang.org/x/text v0.21.0 // indirect
)
