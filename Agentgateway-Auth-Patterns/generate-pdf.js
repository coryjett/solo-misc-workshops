#!/usr/bin/env node
/**
 * Generate Agent-Gateway-Token-Flows.pdf from the markdown source.
 * Uses Puppeteer to render an HTML page with Mermaid diagrams, styled to match
 * the original PDF (blue headers, linked TOC, doc reference footer).
 *
 * Usage: node generate-pdf.js
 */

const fs = require('fs');
const path = require('path');
const puppeteer = require('puppeteer');

const MD_FILE = path.join(__dirname, 'agent-gateway-token-flows.md');
const OUT_FILE = path.join(__dirname, 'Agent-Gateway-Token-Flows.pdf');

function parseMd(md) {
  const sections = [];
  let current = null;
  for (const line of md.split('\n')) {
    if (line.startsWith('## Flow ') || line.startsWith('## Decision ')) {
      if (current) sections.push(current);
      const title = line.replace(/^##\s+/, '');
      current = { title, lines: [] };
    } else if (current) {
      current.lines.push(line);
    }
  }
  if (current) sections.push(current);
  return sections;
}

function renderSection(sec, idx) {
  const body = sec.lines.join('\n');
  // Extract description (first non-empty, non-blockquote, non-code line)
  const descMatch = body.match(/^(?!>|```|\s*$)(.+)/m);
  const desc = descMatch ? descMatch[1].trim() : '';

  // Extract doc links from blockquotes
  const docLinks = [];
  for (const m of body.matchAll(/>\s*\*\*(?:Docs|API):\*\*\s*(.+)/g)) {
    docLinks.push(m[1].replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2">$1</a>').replace(/\s*·\s*/g, ' | '));
  }

  // Extract mermaid blocks
  const mermaidBlocks = [];
  for (const m of body.matchAll(/```mermaid\n([\s\S]*?)```/g)) {
    mermaidBlocks.push(m[1].trim());
  }

  const slug = `flow-${idx}`;
  let html = `<div class="page" id="${slug}">`;
  html += `<div class="section-header"><h2>${sec.title}</h2></div>`;
  if (desc) html += `<p class="desc">${desc.replace(/`([^`]+)`/g, '<code>$1</code>')}</p>`;
  if (docLinks.length) html += `<div class="doc-links">${docLinks.map(d => `<p>${d}</p>`).join('')}</div>`;
  for (const mmd of mermaidBlocks) {
    html += `<div class="mermaid">${mmd}</div>`;
  }
  html += `<p class="back-link"><a href="#toc">&lt; Table of Contents</a></p>`;
  html += `</div>`;
  return html;
}

async function main() {
  const md = fs.readFileSync(MD_FILE, 'utf-8');
  const sections = parseMd(md);

  // Build TOC
  let tocHtml = '';
  sections.forEach((sec, i) => {
    tocHtml += `<tr><td><a href="#flow-${i}">${sec.title}</a></td><td class="page-num"></td></tr>`;
  });

  const html = `<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
  @page { size: letter; margin: 0; }
  * { box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 0; color: #333; font-size: 13px; line-height: 1.5; }
  .page { page-break-before: always; padding: 50px 60px 80px; min-height: 100vh; position: relative; }
  .page:first-child { page-break-before: avoid; }

  /* Title page */
  .title-page { display: flex; flex-direction: column; padding: 0; min-height: 100vh; }
  .title-banner { background: linear-gradient(135deg, #0055b8, #0077dd); color: white; padding: 50px 60px; }
  .title-banner h1 { font-size: 36px; font-weight: 700; margin: 0; letter-spacing: -0.5px; }
  .title-content { padding: 40px 60px; flex: 1; }

  /* TOC */
  #toc { margin-top: 10px; }
  .toc-title { font-size: 16px; font-weight: 600; margin-bottom: 15px; color: #333; }
  .toc-table { width: 100%; border-collapse: collapse; }
  .toc-table td { padding: 6px 0; border-bottom: 1px dotted #ddd; vertical-align: top; }
  .toc-table td:first-child { padding-left: 20px; }
  .toc-table td.page-num { text-align: right; width: 60px; color: #666; }
  .toc-table a { color: #0055b8; text-decoration: none; }
  .toc-table a:hover { text-decoration: underline; }

  /* Section headers */
  .section-header { background: linear-gradient(135deg, #0055b8, #0077dd); color: white; padding: 18px 30px; margin: -50px -60px 25px -60px; }
  .section-header h2 { font-size: 24px; font-weight: 600; margin: 0; }

  /* Content */
  .desc { font-size: 13px; margin: 0 0 8px 0; }
  .doc-links { background: #f0f4ff; border-left: 3px solid #0055b8; padding: 6px 12px; margin: 0 0 15px 0; font-size: 11.5px; }
  .doc-links p { margin: 2px 0; }
  .doc-links a { color: #0055b8; text-decoration: none; }
  .doc-links a:hover { text-decoration: underline; }
  code { background: #f0f0f0; padding: 1px 4px; border-radius: 3px; font-size: 12px; }

  /* Mermaid */
  .mermaid { margin: 15px auto; text-align: center; }
  .mermaid svg { max-width: 100%; }

  /* Footer */
  .page-footer { position: fixed; bottom: 20px; left: 60px; right: 60px; text-align: center; font-size: 10px; color: #888; border-top: 1px solid #eee; padding-top: 8px; }
  .back-link { font-size: 11px; margin-top: 20px; }
  .back-link a { color: #0055b8; text-decoration: none; }
</style>
<script src="https://cdn.jsdelivr.net/npm/mermaid@11/dist/mermaid.min.js"></script>
<script>
  mermaid.initialize({
    startOnLoad: true,
    theme: 'default',
    sequence: { diagramMarginX: 20, diagramMarginY: 10, actorMargin: 60, width: 180, height: 45, boxMargin: 8, noteMargin: 8, messageMargin: 30, mirrorActors: true, useMaxWidth: true },
    flowchart: { useMaxWidth: true, htmlLabels: true, curve: 'basis' }
  });
</script>
</head>
<body>

<!-- Title page -->
<div class="title-page page" style="page-break-before: avoid;">
  <div class="title-banner">
    <h1>Agent Gateway &mdash; Auth Patterns</h1>
  </div>
  <div class="title-content">
    <div id="toc">
      <p class="toc-title">Table of Contents</p>
      <table class="toc-table">
        ${tocHtml}
      </table>
    </div>
  </div>
  <div style="text-align: center; padding: 20px 60px; font-size: 10px; color: #888;">
    Docs: https://docs.solo.io/agentgateway/2.2.x/ &nbsp;|&nbsp; API Reference: https://docs.solo.io/agentgateway/2.2.x/reference/api/solo/
  </div>
</div>

<!-- Flow pages -->
${sections.map((s, i) => renderSection(s, i)).join('\n')}

</body>
</html>`;

  const browser = await puppeteer.launch({ headless: true, args: ['--no-sandbox'] });
  const page = await browser.newPage();
  await page.setContent(html, { waitUntil: 'networkidle0', timeout: 60000 });

  // Wait for Mermaid to render
  await page.waitForFunction(() => {
    const els = document.querySelectorAll('.mermaid');
    return Array.from(els).every(el => el.querySelector('svg'));
  }, { timeout: 30000 });

  await page.pdf({
    path: OUT_FILE,
    format: 'Letter',
    printBackground: true,
    margin: { top: '0', bottom: '0', left: '0', right: '0' },
  });

  await browser.close();
  const stat = fs.statSync(OUT_FILE);
  console.log(`Generated ${OUT_FILE} (${(stat.size / 1024 / 1024).toFixed(1)} MB)`);
}

main().catch(err => { console.error(err); process.exit(1); });
