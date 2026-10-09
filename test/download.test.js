import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { crxUrl, downloadFromUrl } from '../src/download.js';

test('crxUrl builds the chrome update endpoint', () => {
  const url = crxUrl('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'chrome');
  assert.match(url, /^https:\/\/clients2\.google\.com\/service\/update2\/crx\?/);
});

test('crxUrl builds the edge update endpoint', () => {
  const url = crxUrl('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'edge');
  assert.match(url, /^https:\/\/edge\.microsoft\.com\/extensionwebstorebase\/v1\/crx\?/);
});

async function withServer(handler, fn) {
  const server = createServer(handler);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  try {
    await fn(`http://127.0.0.1:${port}/`);
  } finally {
    server.close();
  }
}

test('downloadFromUrl returns the body when the host is allowed', async () => {
  await withServer(
    (req, res) => res.end('crx-bytes'),
    async (url) => {
      const buf = await downloadFromUrl(url, { isAllowedHost: (h) => h === '127.0.0.1' });
      assert.equal(buf.toString(), 'crx-bytes');
    }
  );
});

test('downloadFromUrl rejects a disallowed host', async () => {
  await withServer(
    (req, res) => res.end('crx-bytes'),
    async (url) => {
      await assert.rejects(downloadFromUrl(url, { isAllowedHost: () => false }), /untrusted host/);
    }
  );
});

test('downloadFromUrl rejects a response over the size limit', async () => {
  await withServer(
    (req, res) => {
      res.writeHead(200, { 'Content-Length': '20' });
      res.end('x'.repeat(20));
    },
    async (url) => {
      await assert.rejects(
        downloadFromUrl(url, { isAllowedHost: () => true, maxBytes: 10 }),
        /byte limit/
      );
    }
  );
});

test('downloadFromUrl times out a hanging response', async () => {
  await withServer(
    () => {
      /* never respond */
    },
    async (url) => {
      await assert.rejects(
        downloadFromUrl(url, { isAllowedHost: () => true, timeoutMs: 50 }),
        /timed out/
      );
    }
  );
});

test('downloadFromUrl surfaces a 404 as "not found"', async () => {
  await withServer(
    (req, res) => res.writeHead(404).end(),
    async (url) => {
      await assert.rejects(downloadFromUrl(url, { isAllowedHost: () => true }), /not found/);
    }
  );
});
