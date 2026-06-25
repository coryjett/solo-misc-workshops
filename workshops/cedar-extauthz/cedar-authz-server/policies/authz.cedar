// ───────────────────────────────────────────────────────────────────────────
// Cedar policies — enforced by cedar-go behind agentgateway ext_authz.
// Authorizes on claims from your IdP's client-credentials token:
//   team (-> Group parent), tier, org, scp, sub.
// Demonstrates: team membership, LLM model allowlist, attribute conditions,
// and MCP tool + per-argument constraints. Cedar is default-deny.
// ───────────────────────────────────────────────────────────────────────────

// 1. LLM model allowlist by team + tier.
//    GTM team on the premium tier may use the approved chat models.
permit (
  principal in Group::"GTM",
  action == Action::"llm:chat",
  resource
)
when { resource in [Model::"gpt-4o", Model::"gpt-4o-mini"] }
when { principal.tier == "premium" };

// 1a. Org-wide hard deny of an expensive model (forbid always wins over any permit).
forbid (
  principal,
  action == Action::"llm:chat",
  resource == Model::"gpt-4-turbo"
);

// 2. MCP tool discovery: GTM can list tools on the solo-docs server.
permit (
  principal in Group::"GTM",
  action == Action::"mcp:listTools",
  resource
)
when { resource.server == "solo-docs" };

// 3. MCP per-tool authorization: GTM may call the docs search tool...
permit (
  principal in Group::"GTM",
  action == Action::"mcp:callTool",
  resource == Tool::"search_solo_docs"
);

// 3a. ...but only within the public docs path — a per-ARGUMENT constraint.
//     A tools/call whose `path` argument escapes /docs is denied even for permitted users.
forbid (
  principal,
  action == Action::"mcp:callTool",
  resource == Tool::"search_solo_docs"
)
unless { context.args.path like "/docs*" };

// 4. Explicitly forbid a destructive tool for everyone.
forbid (
  principal,
  action == Action::"mcp:callTool",
  resource == Tool::"delete_page"
);
