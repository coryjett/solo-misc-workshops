---
name: create-demo
description: >
  Prepare a customer demo the standard way: account prep, a chain of existing
  modules, a scannable walkthrough, a diagram tour link and optional HTML deck,
  then a verified end-to-end run. TRIGGER when asked to prep for a customer
  call or demo, build a demo for an account, write a walkthrough, or "what's
  the agenda for <customer>". Reuses the generic modules in
  workshops/agentic-platform-demo; never builds customer-specific code.
---

# Create a customer demo

A customer demo is a **walkthrough that chains generic modules**, not a new build. New capability goes into the repo as a generic module first; the customer only gets a one-page walkthrough.

**Inputs:** customer name, call date and time. Ask only if the calendar and CRM cannot answer.
**Outputs (outside this repo):** `$CUSTOMERS_DIR/<Customer>/call-prep-<date>.md`, `walkthrough-<date>.md`, `architecture.html` (always) and optionally `deck.html`. `CUSTOMERS_DIR` defaults to `~/Documents/Workspace/Customers`.
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

- Open `workshops/agentic-platform-demo/modules/README.md`. Map each ask to a module: G (MCP), L (LLM), A (A2A), K (kagent behind the gateway), P/X (platform, extension), R (registry).
- kagent-first conversation: chain the K modules (K1 overview, K7 build, K2-K6 identity, guardrails, approval, roles, sandbox, K8 tracing, K9 fleet).
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

Decks and architecture diagrams are **demo-specific**: they live in `$CUSTOMERS_DIR/<Customer>/` and the walkthrough links them by **local path only**. No repo links, GitHub Pages or Claude artifact links in a walkthrough.

- **Module-lab demo** (`agentic-platform-demo`): copy `workshops/agentic-platform-demo/environment-diagram.html` to `$CUSTOMERS_DIR/<Customer>/architecture.html` and make it open on this demo's chain (`open` drops `#tour-...` from file URLs, so bake the chain in):
  ```python
  o = 'const start = () => { const c = fromHash(); if (c) { chain = c; i = 0; mode(true); } else mode(false); };'
  n = 'const start = () => { const c = fromHash() || ["P1","G1",...]; chain = c; i = 0; mode(true); };'
  ```
  Link only this local file in the walkthrough; no online diagram link. A new or renamed module still goes into the repo's `environment-diagram.html` (`M` table), and the shared artifact is republished to its same URL for anyone else using it.
- **Any other demo** (a lab outside the modules): build `$CUSTOMERS_DIR/<Customer>/architecture.html` with the same engine as the lab diagram:
  - Copy the `<style>` block and the `<script>` from `environment-diagram.html`.
  - Draw a new inline SVG: one `data-k` key per box, chip and edge; label every arrow.
  - Replace the `M` table with one entry per beat (`t` title, `a` beat, `k` keys to light, `p` what it proves, `s` what they will see), and the parent-box rules in `light()` with this diagram's prefixes.
  - Environment view describes the components; Walkthrough view steps through the beats with arrow keys.
- **Deck (optional):** copy `templates/deck.html` to `$CUSTOMERS_DIR/<Customer>/deck.html`. About 8 slides, plain topic headings, speaker notes in `<aside>` (N toggles them), the architecture as a slide (`id="arch"`).
- **Check every page in a headless browser** before linking it: no script errors, nothing rendered outside the slide stage, no visible `<aside>` notes, each view screenshotted. Wait for transitions (0.2 s) before a screenshot, or lit elements look dim.

## 5. Verify end to end

Do not hand over a walkthrough that has not run.

- **Lab:** `./verify.sh && ./verify-gateway.sh && ./reset.sh` in `agentic-platform-demo`. Run `./reset.sh` again after a rehearsal so the lab is clean for the call.
- **Command-line modules:** `./modules/run-module.sh <ID>` for each module in the chain. Check the output against the card's Expect lines, not just exit codes.
- **UI modules:** `modules/rehearse/kagent.mjs` (K1-K9). Never run `S0` or `reset.sh` while a rehearsal is running: reset deletes the agents under test.
- Fix what fails in the module itself, rerun, commit, push.

## Gotchas (learned the hard way)

- **AI injection guard (L3 webhook):** refuses prompts that ask the agent about its own tools or instructions, prompts that ask a model to repeat a card number, "download this URL", and system prompts with role-play wording ("You are a helpful assistant"). Use task questions ("Look up customer C-1001") and test every live prompt against the gateway three times before the call.
- **Self-hosted model (`auto`):** can return a Cloudflare `524` on slow turns. Agent beats on it need a "start a New chat" fallback in the walkthrough.
- **"MCP" to a model:** ask about "the Model Context Protocol (MCP)", or it may answer "Microsoft Certified Professional".
- **Enterprise kagent 1.x** lives in `solo-io/enterprise-kagent` (calendar versions). The `kagent-enterprise` 0.x repo is the old line; do not judge capability from it.
- **Claims:** anything about product capability is checked against source, docs or release notes before it goes in the walkthrough.

- **Opening local pages:** macOS `open` can drop a `#fragment` from a file URL. Tell the presenter to open the file and click **Walkthrough**, or use arrow keys, rather than relying on `#tour` in the path.
- **GitHub Pages caches:** after removing a page, check the URL returns 404 (`curl -sI`) before saying it is gone; a browser may still show a cached copy.
- **Template edits:** when deriving a template from a real deck, cut at the end of the slide stage, not the first closing tag. Leftover sections outside the stage render their speaker notes to the audience.

## Before committing to this repo

- `git diff --cached -U0 | grep -iE '<customer>|<attendee names>'` must be empty.
- No internal roadmap or product-status news (retirements, unreleased dates) in this repo; it is on GitHub.
- Stage only your paths; other workshops may have uncommitted work.
- Push to main is the norm for this repo; no PR needed.
