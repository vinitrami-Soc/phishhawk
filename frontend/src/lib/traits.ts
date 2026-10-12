/* What links a campaign's messages, as the pages show it. Every value came from
   a reported message: it is defanged as indicators are, and shown as text only.
   The server sends a subject or display name as null once no message's content
   is kept (and always in the list): that reads "Same subject". */

import type { SharedTrait } from '@/api/types';
import { showIndicator } from '@/security/safe';

const KINDS: Record<string, { label: string; type: string }> = {
  attachment: { label: 'Attachment (SHA-256)', type: 'sha256' },
  link: { label: 'Link', type: 'url' },
  domain: { label: 'Domain', type: 'domain' },
  host: { label: 'Host', type: 'domain' },
  qr: { label: 'QR code', type: 'url' },
  sender: { label: 'Sender', type: 'email' },
  'reply-to': { label: 'Reply-to', type: 'email' },
  'sender domain': { label: 'Sender domain', type: 'domain' },
  wallet: { label: 'Wallet', type: 'crypto-wallet' },
  phone: { label: 'Phone number', type: 'phone' },
  subject: { label: 'Subject', type: '' },
  'display name': { label: 'Display name', type: '' },
  'originating IP': { label: 'Originating IP', type: 'ipv4' },
};

export type ShownTrait = { label: string; value: string | null; hidden?: string };

export function sharedTrait(trait: SharedTrait): ShownTrait {
  const known = KINDS[trait.kind];
  const label = known?.label ?? trait.kind;
  if (trait.value === null) return { label, value: null, hidden: `Same ${trait.kind}` };
  return { label, value: known ? showIndicator(known.type, trait.value) : trait.value };
}
