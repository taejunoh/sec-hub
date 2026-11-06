import test from 'node:test';
import assert from 'node:assert/strict';
const policy = await import('../app/policy.mjs').catch(() => ({}));

test('only the exact owned loopback origin can load or open in the browser', () => {
  assert.equal(typeof policy.isOwnedUrl, 'function', 'owned-origin policy must exist');
  const own = 'http://127.0.0.1:43123/';
  for (const url of [own, `${own}assets/app.mjs`, `${own}?x=1#detail`]) assert.equal(policy.isOwnedUrl(url, own), true, url);
  for (const url of ['https://example.com/', 'file:///tmp/run.json', 'javascript:alert(1)', 'http://127.0.0.1.evil.test:43123/', 'http://127.0.0.1:43124/', 'http://localhost:43123/', 'http://user@127.0.0.1:43123/', 'http://2130706433:43123/', 'http://127.0.0.1:43123', '//127.0.0.1:43123/', '', null]) {
    assert.equal(policy.isOwnedUrl(url, own), false, String(url));
    assert.equal(policy.browserUrl(url, own), null, String(url));
  }
  assert.equal(policy.browserUrl(own, own), own);
});

test('unowned or malformed server URLs never establish trust', () => {
  assert.equal(typeof policy.isOwnedUrl, 'function', 'owned-origin policy must exist');
  for (const own of [null, '', 'http://localhost:43123/', 'https://127.0.0.1:43123/', 'http://127.0.0.1:0/', 'http://127.0.0.1:65536/', 'http://127.0.0.1:43123/private', 'http://127.0.0.1:43123/#token']) assert.equal(policy.isOwnedUrl('http://127.0.0.1:43123/', own), false);
});

test('the owned workbench can open canonical OSV advisory URLs only', () => {
  const own = 'http://127.0.0.1:43123/';
  const advisory = 'https://osv.dev/vulnerability/GHSA-29mw-wpgm-hmr9';
  assert.equal(policy.advisoryBrowserUrl(advisory, own, own), advisory);
  assert.equal(policy.advisoryBrowserUrl(advisory, 'http://127.0.0.1:43124/', own), null);
  for (const url of [advisory + '?data=secret', advisory + '#secret', 'https://osv.dev.evil.test/vulnerability/CVE-2020-28500', 'https://user@osv.dev/vulnerability/CVE-2020-28500', 'file:///tmp/run.json', 'https://osv.dev/vulnerability/../list']) {
    assert.equal(policy.advisoryBrowserUrl(url, own, own), null, url);
  }
});
