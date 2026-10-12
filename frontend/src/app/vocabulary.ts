/* Every fixed value the server sends, mapped to words and colours in one place.
   Unknown values are shown as they are, as plain text, in a neutral colour. */

import type { Role, Severity, Verdict } from '@/api/types';

export type Tone = { text: string; tint: string; ring: string };

// written out so Tailwind sees every class name
export const VERDICT_TONE: Record<Verdict, Tone> = {
  MALICIOUS: { text: 'text-v-malicious', tint: 'bg-v-malicious/10', ring: 'border-v-malicious/30' },
  'LIKELY PHISHING': { text: 'text-v-phishing', tint: 'bg-v-phishing/10', ring: 'border-v-phishing/30' },
  SUSPICIOUS: { text: 'text-v-suspicious', tint: 'bg-v-suspicious/10', ring: 'border-v-suspicious/30' },
  'NO STRONG INDICATORS': { text: 'text-v-neutral', tint: 'bg-v-neutral/10', ring: 'border-v-neutral/30' },
};

export const NEUTRAL_TONE: Tone = { text: 'text-v-neutral', tint: 'bg-v-neutral/10', ring: 'border-v-neutral/30' };

export const VERDICT_GLOW: Record<Verdict, string> = {
  MALICIOUS: 'var(--verdict-malicious)',
  'LIKELY PHISHING': 'var(--verdict-phishing)',
  SUSPICIOUS: 'var(--verdict-suspicious)',
  'NO STRONG INDICATORS': 'var(--verdict-neutral)',
};

export const VERDICTS: Verdict[] = ['MALICIOUS', 'LIKELY PHISHING', 'SUSPICIOUS', 'NO STRONG INDICATORS'];

/** What each verdict means, in the order of VERDICTS. Help and the product page both show this. */
export const VERDICT_MEANING: [Verdict, string][] = [
  ['MALICIOUS', 'VirusTotal reports a link or an attachment in the message as malicious. Only possible when an admin has turned VirusTotal on.'],
  ['LIKELY PHISHING', 'Strong evidence: two or more high-severity signals, or one backed by evidence about another part of the message, such as a lookalike sender that also links to a raw IP address.'],
  ['SUSPICIOUS', 'Some evidence, not enough for likely phishing: one high-severity signal on its own, or several smaller ones.'],
  ['NO STRONG INDICATORS', 'Nothing strong was found. This does not prove the message is safe.'],
];

export function verdictTone(verdict: string): Tone {
  return VERDICT_TONE[verdict as Verdict] ?? NEUTRAL_TONE;
}

export const SEVERITY_TONE: Record<Severity, Tone> = {
  high: { text: 'text-s-high', tint: 'bg-s-high/10', ring: 'border-s-high/30' },
  medium: { text: 'text-s-medium', tint: 'bg-s-medium/10', ring: 'border-s-medium/30' },
  low: { text: 'text-s-low', tint: 'bg-s-low/10', ring: 'border-s-low/30' },
};

export const SEVERITY_ORDER: Record<string, number> = { high: 0, medium: 1, low: 2 };

export const ROLE_LABEL: Record<Role, string> = { admin: 'Admin', analyst: 'Analyst' };

export const SOURCE_LABEL: Record<string, string> = {
  upload: 'Upload',
  paste: 'Paste',
  batch: 'Batch',
  mailbox: 'Mailbox',
};

export const PROVIDERS: { id: string; name: string; needsKey: boolean }[] = [
  { id: 'virustotal', name: 'VirusTotal', needsKey: true },
  { id: 'urlscan', name: 'urlscan.io', needsKey: true },
  { id: 'abuseipdb', name: 'AbuseIPDB', needsKey: true },
  { id: 'rdap', name: 'RDAP (domain age)', needsKey: false },
];

export const AUDIT_ACTION: Record<string, string> = {
  login: 'Signed in',
  login_failed: 'Sign-in failed',
  logout: 'Signed out',
  submit: 'Submitted a message',
  analyze: 'Analysis finished',
  analyze_failed: 'Analysis failed',
  download: 'Downloaded a file',
  download_raw: 'Downloaded the raw message',
  reanalyze: 'Re-analyzed',
  delete_tier1: 'Deleted the message, kept the verdict',
  delete_completely: 'Deleted completely',
  hold: 'Put on hold',
  release: 'Released the hold',
  settings: 'Changed settings',
  user_create: 'Added a user',
  user_change: 'Changed a user',
  token_create: 'Created an API token',
  token_revoke: 'Revoked an API token',
  rotate_key: 'Rotated the encryption key',
  retention_sweep: 'Retention clean-up',
};

export const auditLabel = (action: string) => AUDIT_ACTION[action] ?? action;
