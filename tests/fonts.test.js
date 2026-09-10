'use strict';
// Un TTF renommé en .woff2 est rejeté en silence par le navigateur : on vérifie la signature.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const dir = path.join(__dirname, '..', 'fonts');

test('les polices embarquées sont de vrais woff2', () => {
  const files = fs.readdirSync(dir).filter((f) => f.endsWith('.woff2'));
  assert.ok(files.length > 0);
  for (const f of files) {
    assert.equal(fs.readFileSync(path.join(dir, f)).subarray(0, 4).toString('latin1'), 'wOF2', f);
  }
});
