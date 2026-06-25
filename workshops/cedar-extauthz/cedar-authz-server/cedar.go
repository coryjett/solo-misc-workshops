package main

// cedar.go turns an ext_authz CheckRequest into a Cedar authorization query and
// evaluates it against authz.cedar.
//
// ── cedar-go API NOTE ───────────────────────────────────────────────────────
// Pinned to cedar-go v1.8.0 (see go.mod) — verified to compile against that release.
// The calls this file depends on are:
//     cedar.NewPolicySetFromBytes(name, bytes) (*cedar.PolicySet, error)
//     policySet.IsAuthorized(types.EntityGetter, cedar.Request) (cedar.Decision, cedar.Diagnostic)
//     types.NewEntityUID(types.EntityType, types.String) types.EntityUID
//     types.EntityMap (map[EntityUID]Entity, implements EntityGetter)
//     types.Entity{UID, Parents types.EntityUIDSet, Attributes types.Record}
//     types.NewRecord(types.RecordMap) / types.NewEntityUIDSet(...) / cedar.Allow
// If you bump cedar-go and it stops compiling, this is the one file to reconcile.
// ─────────────────────────────────────────────────────────────────────────────

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/cedar-policy/cedar-go"
	"github.com/cedar-policy/cedar-go/types"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
)

type CedarEngine struct {
	policies *cedar.PolicySet
}

// Decision is the flattened result we log + return.
type Decision struct {
	Allowed  bool
	Route    string // "llm" | "mcp" | "unknown"
	User     string
	Action   string
	Resource string
	Detail   string // extra context for the log line (e.g. MCP tool args)
}

func NewCedarEngine(path string) (*CedarEngine, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	ps, err := cedar.NewPolicySetFromBytes("authz.cedar", b)
	if err != nil {
		return nil, err
	}
	return &CedarEngine{policies: ps}, nil
}

// Decide builds the Cedar query from the request and evaluates it.
func (e *CedarEngine) Decide(req *authv3.CheckRequest) (Decision, string) {
	http := req.GetAttributes().GetRequest().GetHttp()
	headers := http.GetHeaders()
	body := http.GetBody()

	// route_type is set by the policy via grpc.contextExtensions (see k8s/30,50).
	routeType := req.GetAttributes().GetContextExtensions()["route_type"]

	claims := principalFromJWT(headers["authorization"])
	sub := claims.Sub
	principal := types.NewEntityUID("User", types.String(orAnon(sub)))

	// Build the entity store. The `team` claim becomes a Group parent so
	// `principal in Group::"<team>"` works in Cedar; tier/org/scp ride as attributes.
	entities := types.EntityMap{}
	parents := make([]types.EntityUID, 0, 1)
	if claims.Team != "" {
		g := types.NewEntityUID("Group", types.String(claims.Team))
		entities[g] = types.Entity{UID: g}
		parents = append(parents, g)
	}
	scp := make([]types.Value, 0, len(claims.Scp))
	for _, s := range claims.Scp {
		scp = append(scp, types.String(s))
	}
	entities[principal] = types.Entity{
		UID:     principal,
		Parents: types.NewEntityUIDSet(parents...),
		Attributes: types.NewRecord(types.RecordMap{
			"sub":  types.String(orAnon(sub)),
			"team": types.String(claims.Team),
			"tier": types.String(claims.Tier),
			"org":  types.String(claims.Org),
			"scp":  types.NewSet(scp...),
		}),
	}

	switch routeType {
	case "llm":
		return e.decideLLM(entities, principal, sub, body)
	case "mcp":
		return e.decideMCP(entities, principal, sub, body)
	default:
		// Fail closed on an unknown route classification.
		return Decision{Allowed: false, Route: "unknown", User: orAnon(sub)},
			"missing or unknown route_type context extension"
	}
}

// ── LLM: OpenAI chat-completions body carries {"model": "...", "stream": bool} ──
func (e *CedarEngine) decideLLM(entities types.EntityMap, principal types.EntityUID, sub, body string) (Decision, string) {
	var b struct {
		Model  string `json:"model"`
		Stream bool   `json:"stream"`
	}
	_ = json.Unmarshal([]byte(body), &b)

	resource := types.NewEntityUID("Model", types.String(b.Model))
	entities[resource] = types.Entity{UID: resource}

	req := cedar.Request{
		Principal: principal,
		Action:    types.NewEntityUID("Action", "llm:chat"),
		Resource:  resource,
		Context: types.NewRecord(types.RecordMap{
			"stream": types.Boolean(b.Stream),
		}),
	}
	dec := Decision{Route: "llm", User: orAnon(sub), Action: "llm:chat", Resource: "Model::" + b.Model}
	return e.eval(entities, req, dec)
}

// ── MCP: StreamableHTTP carries a JSON-RPC body ──
//   tools/list  -> action mcp:listTools
//   tools/call  -> action mcp:callTool, resource = params.name, context.args from params.arguments
func (e *CedarEngine) decideMCP(entities types.EntityMap, principal types.EntityUID, sub, body string) (Decision, string) {
	var rpc struct {
		Method string `json:"method"`
		Params struct {
			Name      string                 `json:"name"`
			Arguments map[string]interface{} `json:"arguments"`
		} `json:"params"`
	}
	_ = json.Unmarshal([]byte(body), &rpc)

	switch rpc.Method {
	case "tools/list", "":
		// the demo MCP backend is the solo-docs server; one synthetic resource carries .server
		resource := types.NewEntityUID("Tool", "*")
		entities[resource] = types.Entity{
			UID:        resource,
			Attributes: types.NewRecord(types.RecordMap{"server": types.String("solo-docs")}),
		}
		req := cedar.Request{
			Principal: principal,
			Action:    types.NewEntityUID("Action", "mcp:listTools"),
			Resource:  resource,
			Context:   types.NewRecord(types.RecordMap{}),
		}
		dec := Decision{Route: "mcp", User: orAnon(sub), Action: "mcp:listTools", Resource: "Tool::*"}
		return e.eval(entities, req, dec)

	case "tools/call":
		resource := types.NewEntityUID("Tool", types.String(rpc.Params.Name))
		entities[resource] = types.Entity{
			UID:        resource,
			Attributes: types.NewRecord(types.RecordMap{"server": types.String("solo-docs")}),
		}
		// flatten a few well-known string args (schema declares path/query/owner)
		path := strArg(rpc.Params.Arguments, "path")
		query := strArg(rpc.Params.Arguments, "query")
		owner := strArg(rpc.Params.Arguments, "owner")
		args := types.NewRecord(types.RecordMap{
			"path":  types.String(path),
			"query": types.String(query),
			"owner": types.String(owner),
		})
		req := cedar.Request{
			Principal: principal,
			Action:    types.NewEntityUID("Action", "mcp:callTool"),
			Resource:  resource,
			Context:   types.NewRecord(types.RecordMap{"args": args}),
		}
		dec := Decision{
			Route: "mcp", User: orAnon(sub), Action: "mcp:callTool",
			Resource: "Tool::" + rpc.Params.Name,
			Detail:   fmt.Sprintf("args.path=%q", path),
		}
		return e.eval(entities, req, dec)

	default:
		// non-tool MCP methods (initialize, ping, ...) are allowed through; authz is about tools.
		return Decision{Allowed: true, Route: "mcp", User: orAnon(sub), Action: rpc.Method}, ""
	}
}

func (e *CedarEngine) eval(entities types.EntityMap, req cedar.Request, dec Decision) (Decision, string) {
	decision, diag := e.policies.IsAuthorized(entities, req)
	dec.Allowed = decision == cedar.Allow
	if dec.Allowed {
		return dec, ""
	}
	return dec, summarizeDiag(diag)
}

// ── helpers ──

// jwtClaims is the subset of the token this demo authorizes on.
// A client-credentials token from your IdP, carrying: sub, team, tier, org, scp.
type jwtClaims struct {
	Sub  string   `json:"sub"`
	Team string   `json:"team"`
	Tier string   `json:"tier"`
	Org  string   `json:"org"`
	Scp  []string `json:"scp"`
	// Fallback: if a user-token carries groups instead of a team claim, map the
	// first group to the team so the same policies work for both token shapes.
	Groups []string `json:"groups"`
}

// principalFromJWT decodes the (already gateway-validated) JWT payload.
// We do NOT verify the signature here — agentgateway validated it upstream. In production,
// prefer having the gateway forward claims as trusted headers or via metadata_context.
func principalFromJWT(authz string) jwtClaims {
	tok := strings.TrimSpace(strings.TrimPrefix(authz, "Bearer "))
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return jwtClaims{}
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return jwtClaims{}
	}
	var c jwtClaims
	if err := json.Unmarshal(payload, &c); err != nil {
		return jwtClaims{}
	}
	if c.Team == "" && len(c.Groups) > 0 {
		c.Team = c.Groups[0]
	}
	return c
}

func strArg(m map[string]interface{}, k string) string {
	if v, ok := m[k]; ok {
		if s, ok := v.(string); ok {
			return s
		}
		return fmt.Sprintf("%v", v)
	}
	return ""
}

func orAnon(s string) string {
	if s == "" {
		return "anonymous"
	}
	return s
}

func summarizeDiag(diag cedar.Diagnostic) string {
	if len(diag.Errors) > 0 {
		return fmt.Sprintf("policy eval errors: %v", diag.Errors)
	}
	if len(diag.Reasons) == 0 {
		return "no permit matched (default deny)"
	}
	ids := make([]string, 0, len(diag.Reasons))
	for _, r := range diag.Reasons {
		ids = append(ids, string(r.PolicyID))
	}
	return "matched forbid policy: " + strings.Join(ids, ",")
}
