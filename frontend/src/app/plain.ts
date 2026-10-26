/* Plain words for someone checking their own mail: the verdict, why, and what
   to do (docs/superpowers/specs/2026-10-26-simple-view-design.md). Fixed text:
   nothing here comes from the message. */

import type { Signal, Verdict } from '@/api/types';
import { SEVERITY_ORDER } from '@/app/vocabulary';

export type PlainVerdict = { headline: string; detail: string };
export type PlainStep = { lead?: string; text: string };

const VERDICTS: Record<Verdict, PlainVerdict> = {
  MALICIOUS: { headline: 'This email is dangerous.', detail: 'Security services already know a link or file in it as harmful.' },
  'LIKELY PHISHING': { headline: 'This email is very likely a scam.', detail: 'It shows several signs that scammers use.' },
  SUSPICIOUS: { headline: 'Be careful with this email.', detail: "Some things look wrong, but we can't be sure." },
  'NO STRONG INDICATORS': {
    headline: 'No warning signs found.',
    detail: "This doesn't prove it's safe: if it asks for money or your password, check with the sender another way.",
  },
};

/** One reason per family of finding: the engine's FAMILIES (src/phishhawk/models.py), kept in step by tests/test_plain_words.py. */
export const REASONS: Readonly<Record<string, string>> = {
  sender: 'The sender pretends to be someone you trust.',
  link: 'A link leads somewhere other than it shows, or to a kind of website often used for scams.',
  attachment: 'An attachment could harm your device or ask for your password.',
  content: 'The wording pushes you to act fast, pay, or sign in.',
  auth: 'The email could not be confirmed as coming from the address it shows.',
  evasion: 'The email hides parts of itself to get past spam filters.',
  intel: 'Security services already report a link or file in this email as harmful.',
  policy: 'It matches a block list or rule set on your account.',
};

export const FALLBACK_REASON = 'Several smaller warning signs add up.';

const SCAM: PlainStep[] = [
  { text: "Don't click any link, open any attachment, or reply." },
  { text: 'Report it as phishing in your email app, then delete it. In the UK you can also forward it to report@phishing.gov.uk.' },
  { lead: 'Already clicked a link or typed a password?', text: 'Change that password now, and anywhere else you use it, and turn on 2-step verification.' },
  { lead: 'Shared bank or card details?', text: 'Call your bank on the number on the back of your card.' },
];

const STEPS: Record<Verdict, PlainStep[]> = {
  MALICIOUS: SCAM,
  'LIKELY PHISHING': SCAM,
  SUSPICIOUS: [
    { text: "Don't click links or open attachments yet." },
    { text: 'Check with the sender another way: call them, or type their website address yourself.' },
    { text: 'If it turns out to be fake, report it as phishing and delete it.' },
  ],
  'NO STRONG INDICATORS': [{ text: 'If it asks for money, a password or urgent action, check with the sender another way first.' }],
};

/** A verdict this version does not know is treated like SUSPICIOUS. */
function known(verdict: string): Verdict {
  return Object.hasOwn(VERDICTS, verdict) ? (verdict as Verdict) : 'SUSPICIOUS';
}

export function plainVerdict(verdict: string): PlainVerdict {
  return VERDICTS[known(verdict)];
}

export function plainSteps(verdict: string): PlainStep[] {
  return STEPS[known(verdict)];
}

/** Up to three reasons, the most serious finding of each family first; none for a message with no warning signs. */
export function plainReasons(verdict: string, signals: Pick<Signal, 'severity' | 'family'>[]): string[] {
  if (verdict === 'NO STRONG INDICATORS') return [];
  const reasons: string[] = [];
  const bySeverity = [...signals].sort((a, b) => (SEVERITY_ORDER[a.severity] ?? 9) - (SEVERITY_ORDER[b.severity] ?? 9));
  for (const { family } of bySeverity) {
    const reason = family && Object.hasOwn(REASONS, family) ? REASONS[family] : undefined;
    if (reason && !reasons.includes(reason)) reasons.push(reason);
    if (reasons.length === 3) break;
  }
  return reasons.length ? reasons : [FALLBACK_REASON];
}
