// Real-browser integration test. Explicit isolated root; never uses personal profiles.
import fs from 'node:fs/promises';
import path from 'node:path';
import { spawn, execFileSync } from 'node:child_process';
import assert from 'node:assert/strict';
const [program, root, channel] = process.argv.slice(2);
if (!program || !root || !channel) throw new Error('usage: browser-smoke <exe> <isolated-root> <normal|antidetect>');
const planProgram = path.resolve(import.meta.dirname, '../launcher/src-tauri/target/debug/examples/browser_plan.exe');
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));
const plan = mode => JSON.parse(execFileSync(planProgram, [root, channel, ...(mode ? [mode] : [])], { encoding: 'utf8' }));
let child;
let port;
let errors = [];
function connect(url) {
  const ws = new WebSocket(url);
  let seq = 0;
  const pending = new Map();
  const ready = new Promise((resolve, reject) => { ws.onopen = resolve; ws.onerror = reject; });
  ws.onmessage = event => {
    const data = JSON.parse(event.data);
    const request = pending.get(data.id);
    if (request) { pending.delete(data.id); data.error ? request.reject(new Error(JSON.stringify(data.error))) : request.resolve(data.result); }
  };
  return {
    async send(method, params = {}) {
      await ready;
      return new Promise((resolve, reject) => {
        const id = ++seq;
        const timer = setTimeout(() => { pending.delete(id); reject(new Error(`CDP timeout: ${method}`)); }, 15000);
        pending.set(id, { resolve: result => { clearTimeout(timer); resolve(result); }, reject: error => { clearTimeout(timer); reject(error); } });
        ws.send(JSON.stringify({ id, method, params }));
      });
    },
    close() { ws.close(); }
  };
}
async function targets() { return (await (await fetch(`http://127.0.0.1:${port}/json/list`)).json()).filter(x => x.type === 'page'); }
async function waitFor(test, label) {
  for (let i = 0; i < 120; i++) {
    try { const value = await test(); if (value) return value; } catch {}
    await pause(250);
  }
  throw new Error(`Timed out: ${label}\n${errors.join('').slice(-3000)}`);
}
async function launch(mode) {
  const args = plan(mode);
  const data = args.find(a => a.startsWith('--user-data-dir=')).split('=').slice(1).join('=');
  const portFile = path.join(data, 'DevToolsActivePort');
  await fs.rm(portFile, { force: true });
  errors = [];
  child = spawn(program, [...args, '--headless=new', '--remote-debugging-port=0', '--window-size=1280,900'], { windowsHide: true, stdio: ['ignore', 'ignore', 'pipe'] });
  child.stderr.on('data', chunk => errors.push(String(chunk)));
  port = await waitFor(async () => Number((await fs.readFile(portFile, 'utf8')).split('\n')[0]), 'debug port');
  await waitFor(async () => (await targets()).length, 'first page');
  return args;
}
async function close() {
  const info = await (await fetch(`http://127.0.0.1:${port}/json/version`)).json();
  const client = connect(info.webSocketDebuggerUrl);
  await client.send('Browser.close');
  client.close();
  await waitFor(() => child.exitCode !== null || child.signalCode !== null, 'browser exit');
  plan('seal');
}
try {
  await launch();
  const first = (await targets())[0];
  const client = connect(first.webSocketDebuggerUrl);
  let lastPage;
  const rendered = await waitFor(async () => {
    const result = await client.send('Runtime.evaluate', { expression: `JSON.stringify({ title: document.title, url: location.href, inputs: document.querySelectorAll('input').length, clock: document.querySelector('time')?.textContent, logo: document.querySelector('.logo')?.complete, scripts: [...document.scripts].map(x => x.src) })` });
    const page = JSON.parse(result.result.value);
    lastPage = page;
    return page.title === 'FousBrowser' && page.clock ? page : false;
  }, 'FousBrowser new-tab content').catch(error => { client.close(); throw new Error(`${error.message}\nPage: ${JSON.stringify(lastPage)}\nTarget: ${JSON.stringify(first)}`); });
  assert.equal(rendered.inputs, 1);
  assert.equal(rendered.logo, true);
  assert.match(rendered.url, /^(file|chrome-extension):\/\//);
  const screenshot = await client.send('Page.captureScreenshot', { format: 'png' });
  await fs.writeFile(path.join(root, 'newtab.png'), Buffer.from(screenshot.data, 'base64'));
  client.close();
  const nextTab = await (await fetch(`http://127.0.0.1:${port}/json/new?${encodeURIComponent('chrome://newtab/')}`, { method: 'PUT' })).json();
  const nextClient = connect(nextTab.webSocketDebuggerUrl);
  const nextPage = await waitFor(async () => {
    const result = await nextClient.send('Runtime.evaluate', { expression: `JSON.stringify({title:document.title,url:location.href,clock:document.querySelector('time')?.textContent})` });
    const page = JSON.parse(result.result.value);
    return page.title === 'FousBrowser' && page.clock ? page : false;
  }, 'every newly created tab uses FousBrowser');
  assert.match(nextPage.url, /^chrome-extension:\/\//);
  nextClient.close();
  await fetch(`http://127.0.0.1:${port}/json/close/${nextTab.id}`);
  const created = await (await fetch(`http://127.0.0.1:${port}/json/new?${encodeURIComponent('chrome://version/')}`, { method: 'PUT' })).json();
  await waitFor(async () => (await targets()).find(t => t.id === created.id), 'second tab');
  assert.equal((await targets()).length, 2);
  await close();
  await launch();
  await waitFor(async () => (await targets()).length === 2, 'restored two tabs');
  const restored = await targets();
  assert.ok(restored.some(t => t.url === 'chrome://version/'));
  assert.ok(restored.some(t => /chrome:\/\/newtab|chrome-extension:|file:/.test(t.url)));
  await close();
  await launch();
  await waitFor(async () => (await targets()).length === 2, 'second restoration without duplicate tabs');
  await close();
  const freshArgs = await launch('fresh');
  assert.ok(!freshArgs.includes('--restore-last-session'));
  await pause(2000);
  const fresh = await targets();
  // Disabling forced restore delegates startup to the browser's native settings.
  assert.ok(fresh.length >= 1);
  await close();
  console.log(JSON.stringify({ channel, status: 'passed', rendered, checks: ['newtab override', 'local clock and assets', 'restore two tabs after vault seal/unseal', 'no duplicate tabs after second restart', 'disable forced restoration delegates to browser'] }, null, 2));
} catch (error) {
  if (child && child.exitCode === null) {
    try { await close(); } catch { child.kill(); }
  }
  throw error;
}
