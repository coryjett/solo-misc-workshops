---
name: create-demo
description: >
  Prepare a customer demo the standard way: account prep, a chain of existing
  modules, a scannable walkthrough, a diagram tour link and optional HTML deck,
  then a verified end-to-end run. TRIGGER when asked to prep for a customer
  call or demo, build a demo for an account, write a walkthrough, or "what's
  the agenda for <customer>". Reuses the generic modules in
  workshops/agentic-platform-demo and the kagent kit in
  workshops/kagent-enterprise-demo; never builds customer-specific code.
---

# Create a customer demo

A customer demo is a **walkthrough that chains generic modules**, not a new build. New capability goes into the repo as a generic module first; the customer only gets a one-page walkthrough.

**Inputs:** customer name, call date and time. Ask only if the calendar and CRM cannot answer.
**Outputs (outside this repo):** `$CUSTOMERS_DIR/<Customer>/call-prep-<date>.md` and `walkthrough-<date>.md`. `CUSTOMERS_DIR` defaults to `~/Documents/Workspace/Customers`.
**Outputs (inside this repo):** only generic modules, fixes and rehearsal checks. Never a customer, prospect or person name.

## 1. Account prep

Gather, then write `templates/call-prep.md` filled in:

- **Meeting:** the CRM's upcoming meetings (time, attendees, meeting link, AI summary).
- **History:** recent call briefs and emails for the account. Read the briefs, not just previews.
- **Their words:** what they asked to see, quoted where possible. This drives the chain.
- **Environment:** Kubernetes flavour, cloud vs on-prem, IdP, model providers, existing gateways.
- **Owed:** promises from the last call, by owner.

If a source is unreachable (mail or calendar scope), say which and carry on with the rest. Do not guess what an unread email says.

## 2. Pick the chain

- Open `workshops/agentic-platform-demo/modules/README.md`. Map each ask to a module: G (MCP), L (LLM), A (A2A), K (kagent behind the gateway), P/X (platform, extension), R (registry, being retired).
- kagent-first conversation, own small cluster, role switching in the UI: use `workshops/kagent-enterprise-demo` (DEMO.md beats 0-6) instead.
- Aim for about 40 minutes plus questions. Start with S0. End with P2 (observability) when the gateway is in play.
- **Gap?** Build a generic module card (Framing, Proves, Needs, Steps, Say, Don't claim, Cleanup), add it to the module README table and the diagram's `M` table, add a rehearsal check, run it, commit. Then reference it. Never put customer logic in the repo.

## 3. Walkthrough

Copy `templates/walkthrough.md` to `$CUSTOMERS_DIR/<Customer>/walkthrough-<date>.md` and fill it in.

Rules (the reader is presenting live):
- Header line, then bold labels. One fact per bullet. Short table cells.
- No em dashes, no arrows in prose. No "Claude-isms".
- Link each module to its rendered page: `https://coryjett.github.io/solo-misc-workshops/workshops/agentic-platform-demo/modules/<ID>-<slug>.html`.
- Every "Say" line must be true of the running lab. Anything not shown live goes under **Don't claim**.

## 4. Demo pages

- **Diagram tour:** `https://claude.ai/artifact/GioU2sMc25yq8szmCvGgFW#tour-<IDs joined by ->` (generic, safe for any customer). Source: `workshops/agentic-platform-demo/environment-diagram.html`. A new or renamed module must be added to its `M` table and republished to the **same URL**.
- **Deck (optional):** copy `workshops/kagent-enterprise-demo/deck.html` as the template (1920x1080 stage, arrow keys, N for notes). Keep it to about 8 slides, plain topic headings, generic content. A customer-specific deck stays in `$CUSTOMERS_DIR`, not the repo.

## 5. Verify end to end

Do not hand over a walkthrough that has not run.

- **Lab:** `./verify.sh && ./verify-gateway.sh && ./reset.sh` in `agentic-platform-demo` (or `demo/start.sh` in the kagent kit).
- **Command-line modules:** `./modules/run-module.sh <ID>` for each module in the chain. Check the output against the card's Expect lines, not just exit codes.
- **UI modules:** `modules/rehearse/kagent.mjs` (K1-K9) or `kagent-enterprise-demo/demo/rehearse/rehearse.mjs` (kit). Never run `S0` or `reset.sh` while a rehearsal is running: reset deletes the agents under test.
- Fix what fails in the module itself, rerun, commit, push.

## Gotchas (learned the hard way)

- **AI injection guard (L3 webhook):** refuses prompts that ask the agent about its own tools or instructions, prompts that ask a model to repeat a card number, "download this URL", and system prompts with role-play wording ("You are a helpful assistant"). Use task questions ("Look up customer C-1001") and test every live prompt against the gateway three times before the call.
- **Self-hosted model (`auto`):** can return a Cloudflare `524` on slow turns. Agent beats on it need a "start a New chat" fallback in the walkthrough.
- **"MCP" to a model:** ask about "the Model Context Protocol (MCP)", or it may answer "Microsoft Certified Professional".
- **Enterprise kagent 1.x** lives in `solo-io/enterprise-kagent` (calendar versions). The `kagent-enterprise` 0.x repo is the old line; do not judge capability from it.
- **Claims:** anything about product capability is checked against source, docs or release notes before it goes in the walkthrough.

## Before committing to this repo

- `git diff --cached -U0 | grep -iE '<customer>|<attendee names>'` must be empty.
- Stage only your paths; other workshops may have uncommitted work.
- Push to main is the norm for this repo; no PR needed.
