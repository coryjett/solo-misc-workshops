// Small helpers for Ant Design selects in the kagent UI.
export async function pick(p, index, text, { multi = false } = {}) {
  const s = p.locator('.ant-select').nth(index);
  await s.click();
  await p.waitForTimeout(400);
  if (text) { await p.keyboard.type(text); await p.waitForTimeout(500); }
  const opt = p.locator('.ant-select-dropdown:not(.ant-select-dropdown-hidden) .ant-select-item-option').filter({ hasText: text || '' }).first();
  await opt.click();
  await p.waitForTimeout(300);
  if (multi) await p.keyboard.press('Escape');
}
export async function options(p, index) {
  const s = p.locator('.ant-select').nth(index);
  await s.click();
  await p.waitForTimeout(600);
  const o = await p.$$eval('.ant-select-dropdown:not(.ant-select-dropdown-hidden) .ant-select-item-option', e => e.map(x => x.textContent.trim()));
  await p.keyboard.press('Escape');
  return o;
}
