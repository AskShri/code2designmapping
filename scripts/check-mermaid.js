// Usage: npm i mermaid playwright && node scripts/check-mermaid.js <dir-with-mmd-files>
// Parses and renders every .mmd file in a headless Chromium; exits non-zero on the first syntax error.
const { chromium } = require('playwright');
const fs = require('fs');
(async () => {
  const dir = process.argv[2];
  const files = fs.readdirSync(dir).filter(f => f.endsWith('.mmd'));
  const browser = await chromium.launch();
  const page = await browser.newPage();
  await page.setContent(`<html><body></body></html>`); await page.addScriptTag({ content: fs.readFileSync(require.resolve("mermaid/dist/mermaid.min.js"), "utf8") });
  await page.waitForFunction(() => window.mermaid, null, { timeout: 60000 });
  let failed = 0;
  for (const f of files) {
    const src = fs.readFileSync(`${dir}/${f}`, 'utf8');
    const res = await page.evaluate(async (src) => {
      try { await window.mermaid.parse(src); const r = await window.mermaid.render('x' + Math.random().toString(36).slice(2), src); return { ok: true, len: r.svg.length }; }
      catch (e) { return { ok: false, err: String(e.message || e) }; }
    }, src);
    console.log(f, res.ok ? `ok (svg ${res.len} bytes)` : `FAIL: ${res.err}`);
    if (!res.ok) failed++;
  }
  await browser.close();
  process.exit(failed ? 1 : 0);
})();
