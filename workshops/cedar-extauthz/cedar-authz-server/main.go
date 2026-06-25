// cedar-authz-server is an ext_authz gRPC service that delegates authorization
// decisions to Cedar (cedar-go), wired behind agentgateway via
// EnterpriseAgentgatewayPolicy.traffic.extAuth.
//
// agentgateway is a standalone Rust proxy that speaks the standard external-authorization
// (ext_authz) gRPC contract, so we implement that Authorization/Check service and agentgateway
// calls us for the decision. (The Go stubs come from go-control-plane.)
package main

import (
	"context"
	"log"
	"net"
	"os"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	rpcstatus "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/reflection"
)

type server struct {
	authv3.UnimplementedAuthorizationServer
	engine *CedarEngine
}

// Check is invoked by agentgateway for every request on a route that has
// traffic.extAuth pointed at this service.
func (s *server) Check(ctx context.Context, req *authv3.CheckRequest) (*authv3.CheckResponse, error) {
	dec, reason := s.engine.Decide(req)
	detail := ""
	if dec.Detail != "" {
		detail = " " + dec.Detail
	}
	if dec.Allowed {
		log.Printf("ALLOW  route=%s user=%s action=%s resource=%s%s", dec.Route, dec.User, dec.Action, dec.Resource, detail)
		return allow(), nil
	}
	log.Printf("DENY   route=%s user=%s action=%s resource=%s%s reason=%q", dec.Route, dec.User, dec.Action, dec.Resource, detail, reason)
	return deny(reason), nil
}

func allow() *authv3.CheckResponse {
	return &authv3.CheckResponse{
		Status: &rpcstatus.Status{Code: int32(codes.OK)},
		HttpResponse: &authv3.CheckResponse_OkResponse{
			OkResponse: &authv3.OkHttpResponse{},
		},
	}
}

func deny(reason string) *authv3.CheckResponse {
	return &authv3.CheckResponse{
		Status: &rpcstatus.Status{Code: int32(codes.PermissionDenied)},
		HttpResponse: &authv3.CheckResponse_DeniedResponse{
			DeniedResponse: &authv3.DeniedHttpResponse{
				Status: &typev3.HttpStatus{Code: typev3.StatusCode_Forbidden},
				Body:   "denied by Cedar policy: " + reason + "\n",
			},
		},
	}
}

func main() {
	addr := envOr("LISTEN_ADDR", ":9090")
	policyPath := envOr("CEDAR_POLICY", "/policies/authz.cedar")

	engine, err := NewCedarEngine(policyPath)
	if err != nil {
		log.Fatalf("loading Cedar policies from %s: %v", policyPath, err)
	}

	lis, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("listen %s: %v", addr, err)
	}

	gs := grpc.NewServer()
	authv3.RegisterAuthorizationServer(gs, &server{engine: engine})
	reflection.Register(gs) // lets grpcurl introspect the service for smoke tests
	log.Printf("cedar-authz-server (ext_authz) listening on %s, policies=%s", addr, policyPath)
	if err := gs.Serve(lis); err != nil {
		log.Fatalf("serve: %v", err)
	}
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
