/* Helpers for attacker-controlled values (frontend build brief, section 5.2).
   Display only: never pass an indicator to href, src, fetch, window.open,
   location, CSS or a download URL. Copy the displayed (defanged) text only. */

const INDICATOR_TYPES = new Set(['url', 'domain', 'ipv4', 'ipv6', 'email', 'sha256', 'crypto-wallet', 'phone']);

const ALLOWED_ATTACK_ID = /^T\d{4}(?:\.\d{3})?$/;

// The engine's rule: hxxp(s):// for the scheme, [.] for every dot in the host.
export function defangUrl(value: string): string {
  const text = String(value);
  const match = text.match(/^(https?|hxxps?|ftp):\/\/([^/?#]+)(.*)$/i);
  if (!match) return defangDomain(text);
  const scheme = match[1].toLowerCase();
  const safeScheme = scheme === 'ftp' ? 'ftp' : scheme.endsWith('s') ? 'hxxps' : 'hxxp';
  return `${safeScheme}://${defangDomain(match[2])}${match[3]}`;
}

export function defangDomain(value: string): string {
  return String(value).split('.').join('[.]');
}

export function defangEmail(value: string): string {
  return String(value).split('@').join('[@]').split('.').join('[.]');
}

/** For iocs[].value. URLs from report.urls already carry `defanged`: use that instead. */
export function showIndicator(type: string, value: string): string {
  const text = String(value);
  if (!INDICATOR_TYPES.has(type)) return text;
  if (type === 'url') return defangUrl(text);
  if (type === 'domain' || type === 'ipv4') return defangDomain(text);
  if (type === 'email') return defangEmail(text);
  return text;
}

/** The only external link the app builds. null for anything that is not a technique ID. */
export function attackUrl(id: string): string | null {
  const techniqueId = String(id);
  if (!ALLOWED_ATTACK_ID.test(techniqueId)) return null;
  return `https://attack.mitre.org/techniques/${techniqueId.replace('.', '/')}/`;
}
