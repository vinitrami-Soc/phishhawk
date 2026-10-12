import assert from 'node:assert/strict';
import { test } from 'node:test';
import { fileUrl, rawMessageUrl } from '../api/client';
import { attackUrl, defangUrl, showIndicator } from '../security/safe';

test('indicators are shown defanged', () => {
  assert.equal(defangUrl('https://evil-login.top/login?next='), 'hxxps://evil-login[.]top/login?next=');
  assert.equal(defangUrl('http://a.b.example/x.php'), 'hxxp://a[.]b[.]example/x.php');
  assert.equal(showIndicator('domain', 'sso.example-corp.top'), 'sso[.]example-corp[.]top');
  assert.equal(showIndicator('ipv4', '203.0.113.7'), '203[.]0[.]113[.]7');
  assert.equal(showIndicator('email', 'it-servicedesk@example-corp.co.uk'), 'it-servicedesk[@]example-corp[.]co[.]uk');
  assert.equal(showIndicator('sha256', 'ab'.repeat(32)), 'ab'.repeat(32));
});

test('ATT&CK links are built only from technique IDs', () => {
  assert.equal(attackUrl('T1566'), 'https://attack.mitre.org/techniques/T1566/');
  assert.equal(attackUrl('T1566.002'), 'https://attack.mitre.org/techniques/T1566/002/');
  for (const bad of ['javascript:alert(1)', 'https://evil.example/', 'T1566/../../x', 't1566', 'T1566.2', ' T1566', '']) {
    assert.equal(attackUrl(bad), null, bad);
  }
});

test('file URLs come from the analysis id and the server file name only', () => {
  assert.equal(
    fileUrl(6, 'phishhawk-report-372d0d6e533b-20261007.html'),
    '/api/v1/analyses/6/files/phishhawk-report-372d0d6e533b-20261007.html',
  );
  assert.equal(fileUrl(6, 'a b/../c.json', true), '/api/v1/analyses/6/files/a%20b%2F..%2Fc.json?download=1');
  assert.equal(rawMessageUrl(9), '/api/v1/messages/9/raw');
});
