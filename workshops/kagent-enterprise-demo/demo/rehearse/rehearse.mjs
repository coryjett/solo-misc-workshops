// Full UI rehearsal of the Enterprise demo, from demo/reset.sh state. Screenshots in rehearsal/.
import { chromium } from 'playwright-core';
import { execSync } from 'node:child_process';
import { pick } from './lib.mjs';
const KC = new URL('../../kubeconfig', import.meta.url).pathname;   // this folder's kubeconfig
const k = (c) => execSync(`kubectl --kubeconfig ${KC} ${c}`).toString().trim();
const b = await chromium.launch({ executablePath: '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome' });
const p = await b.newPage({ viewport: { width: 1600, height: 1200 } });
const results = [];
const check = (name, ok, detail = '') => { results.push(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? '  (' + detail + ')' : ''}`); };
const go = async (u) => { await p.goto('http://localhost:8001' + u, { waitUntil: 'domcontentloaded' }); await p.waitForTimeout(4000); };
const shot = (n) => p.screenshot({ path: `shots/${n}.png`, fullPage: true });
const settle = async () => { await p.waitForTimeout(4000); for (let i = 0; i < 60; i++) { if (!await p.getByRole('button', { name: /Stop|Cancel request/ }).count() || await p.getByRole('button', { name: 'Approve' }).count()) break; await p.waitForTimeout(2000); } await p.waitForTimeout(1500); };
const send = async (msg) => { await p.getByPlaceholder('Ask the agent something…').fill(msg); await p.getByRole('button', { name: 'Send', exact: true }).click(); await settle(); };
const role = async (r) => { await p.getByText('Signed in').click(); await p.waitForTimeout(800); await p.getByText(r, { exact: true }).click(); await p.waitForTimeout(4000); };
const main = async () => (await p.locator('main').innerText());

// Beat 0: dashboard
await go('/'); await shot('0-dashboard'); check('dashboard loads', /Total Agent Runs/.test(await main()));

// Beat 1: create template and agent in the UI
await go('/agents'); await shot('1a-agents-overview');
await go('/agent-templates/new');
await p.getByPlaceholder('incident-responder').fill('ops-assistant');
await pick(p, 1, 'default-model-config');
await p.getByPlaceholder('What this agent is for.').fill('Kubernetes operations assistant for the platform team');
await p.locator('textarea').first().fill('You are a Kubernetes operations assistant. Answer briefly.\nUse your tools to look things up; never guess.');
await p.getByRole('button', { name: 'Add an MCP server' }).click(); await p.waitForTimeout(500);
await pick(p, 4, 'kagent-tool-server'); await p.waitForTimeout(800);
for (const t of ['k8s_get_resources', 'k8s_describe_resource', 'k8s_get_pod_logs', 'k8s_get_events']) await pick(p, 5, t, { multi: true });
await p.getByRole('button', { name: 'Add an MCP server' }).click(); await p.waitForTimeout(500);
await pick(p, 6, 'kagent-tool-server'); await p.waitForTimeout(800);
await pick(p, 7, 'k8s_scale', { multi: true });
await p.getByLabel('Require approval').nth(1).check();
await shot('1b-template-form');
await p.getByRole('button', { name: 'Create template' }).click(); await p.waitForTimeout(3500);
check('template created in UI', k('-n kagent get agenttemplate ops-assistant -o name') === 'agenttemplate.api.kagent.dev/ops-assistant');
await go('/agents/new');
await p.getByPlaceholder('my-agent').fill('ops-assistant');
let labels = await p.$$eval('.ant-select', e => e.map(x => x.textContent.trim()));
await pick(p, labels.findIndex(l => /Choose a template/.test(l)), 'ops-assistant');
await shot('1c-agent-form');
await p.getByRole('button', { name: 'Create agent' }).click(); await p.waitForTimeout(3000);
execSync(`kubectl --kubeconfig ${KC} -n kagent wait agent/ops-assistant --for=condition=Ready --timeout=180s`);
check('agent Ready', true);

// Beat 2: chat, then approval on a change
await go('/agents/kagent/ops-assistant/new');
await send('List the pods in the shop namespace with their status.');
check('read-only tool answer', /k8s_get_resources/.test(await main()) && /web-/.test(await main()));
await shot('2a-chat-read');
await go('/agents/kagent/ops-assistant/new');
await send('Scale the web deployment in the shop namespace to 1 replica.');
const asked = await p.getByRole('button', { name: 'Approve' }).count() > 0;
check('approval prompt shown', asked); await shot('2b-approval');
if (asked) { await p.getByRole('button', { name: 'Approve' }).click(); await settle(); }
check('scale applied after approve', k('-n shop get deploy web -o jsonpath={.spec.replicas}') === '1'); await shot('2c-approved');

// Beat 3: tracing and analytics
await go('/tracing'); await shot('3a-traces');
check('traces listed', /ops-assistant/.test(await main()));
await p.locator('main tbody tr').filter({ hasText: 'ops-assistant' }).first().click(); await p.waitForTimeout(4000);
check('trace detail shows tool span', /execute_tool/.test(await main())); await shot('3b-trace-detail');
await go('/agents/kagent/ops-assistant/analytics'); await shot('3c-analytics');

// Beat 4: access control by role
await role('Reader'); await go('/agents/kagent/ops-assistant/new');
check('reader cannot chat', /Not authorized/.test(await main())); await shot('4a-reader');
await role('Writer'); await go('/agents/kagent/ops-assistant/new');
await send('How many pods are in the shop namespace? Just the number.');
check('writer can chat', /k8s_get_resources/.test(await main())); await shot('4b-writer-chat');
await go('/agent-templates/new'); await p.getByPlaceholder('incident-responder').fill('writer-test');
await p.getByRole('button', { name: 'Create template' }).click(); await p.waitForTimeout(3000);
check('writer cannot create template', /Not authorized/.test(await p.locator('body').innerText())); await shot('4c-writer-denied');
await role('Admin');

// Beat 4b: same agent, the gateway decides the tools (Change role)
const askCo = async (msg) => {
  await go('/agents/kagent/company-assistant/new'); await send(msg);
  const t = await main(); const i = t.lastIndexOf(msg.slice(0, 30)); const j = t.indexOf('AGENT TEMPLATE', i); return t.slice(i, j > 0 ? j : undefined);
};
const TOOLS = 'Which company system tools do you have? List their names only.';
await role('Admin');
let co = await askCo(TOOLS); await shot('4b-admin-tools');
check('4b admin sees records and inventory', /records_lookup_customer/.test(co) && /inventory_check_stock/.test(co));
co = await askCo('Look up customer C-1001.'); await shot('4b-admin-lookup');
check('4b admin lookup masked by gateway', /Jordan Rivera/.test(co) && /DOB REDACTED/.test(co));
await role('Writer');
co = await askCo(TOOLS); await shot('4b-writer-tools');
check('4b writer sees inventory only', /inventory_check_stock/.test(co) && !/records_lookup_customer/.test(co));
co = await askCo('Look up customer C-1001.'); await shot('4b-writer-lookup');
check('4b writer cannot reach records', !/Jordan Rivera/.test(co));
await role('Admin');

// Beat 5: sandbox and egress
await go('/agents/kagent/ops-assistant/new');
await send('Using bash, run exactly: uname -r; wget -q -T 8 -O - https://example.com | head -c 60; echo . Show the output verbatim.');
let t = await main();
check('gVisor kernel visible', /gvisor/.test(t)); check('egress blocked by default', /bad address 'example.com'/.test(t)); await shot('5a-blocked');
await go('/policies/egress/new');
await p.getByPlaceholder('github-api').fill('allow-example-com');
await p.getByPlaceholder('https://api.example.com').fill('https://example.com');
await shot('5b-egress-form');
await p.getByRole('button', { name: 'Create policy' }).click(); await p.waitForTimeout(3000);
await go('/agents/kagent/ops-assistant/edit');
labels = await p.$$eval('.ant-select', e => e.map(x => x.textContent.trim()));
await pick(p, labels.findIndex(l => /No extra hosts/.test(l)), 'allow-example-com', { multi: true });
await shot('5c-attach');
await p.getByRole('button', { name: /Save|Update agent/ }).first().click(); await p.waitForTimeout(3000);
execSync(`kubectl --kubeconfig ${KC} -n kagent wait agent/ops-assistant --for=condition=Ready --timeout=120s`);
await go('/agents/kagent/ops-assistant/new');
await send('Using bash, run exactly: wget -q -T 8 -O - https://example.com | head -c 60; echo; echo ---; wget -q -T 8 -O - https://www.google.com | head -c 60; echo . Show the output verbatim.');
t = await main();
check('allowed host reachable', /<!doctype html>/i.test(t)); check('other host still blocked', /bad address 'www.google.com'/.test(t)); await shot('5d-allowed');

// Beat 6: Substrate view
await go('/substrate'); await shot('6-substrate');
check('substrate page shows actors', /Actors running/.test(await main()));

await b.close();
console.log(results.join('\n'));
console.log(results.some(r => r.startsWith('FAIL')) ? 'RESULT: FAIL' : 'RESULT: ALL PASS');
// Run: cd demo/rehearse && npm i && mkdir -p shots && node rehearse.mjs   (UI on http://localhost:8001, start from demo/reset.sh)
