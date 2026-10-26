/* How someone gets an email out of their mail app: in short on the simple
   upload page, in full on the Help page (docs/superpowers/specs/
   2026-10-26-simple-view-design.md, section 4). The menu names are each
   provider's; check them again when a provider changes its menus. */

import { Card, SectionTitle } from '@/components/ui/ui';

export const MAIL_APPS: { app: string; where: string; steps: string[]; after: string }[] = [
  {
    app: 'Gmail',
    where: 'on a computer',
    steps: ['Open the email.', 'Click ⋮ (More), next to Reply.', 'Choose Download message.', 'Drop the downloaded file into PhishHawk.'],
    after: 'Or choose Show original instead, click Copy to clipboard, and paste it with Paste the message.',
  },
  {
    app: 'Outlook',
    where: 'Outlook.com or Outlook on the web',
    steps: [
      'Open the email.',
      'Click … (More actions).',
      'Choose Download, then Download as EML. (Some versions say Save as, then Save as EML.)',
      'Drop the downloaded file into PhishHawk.',
    ],
    after:
      'A file saved from Outlook can leave out the hidden lines that show who really sent the email. PhishHawk still checks its links, attachments and wording.',
  },
  {
    app: 'Apple Mail',
    where: 'Mac',
    steps: ['Select the email.', 'Choose File, then Save As.', 'Set Format to Raw Message Source, and save.', 'Drop the saved file into PhishHawk.'],
    after: 'Or drag the email from the list to your desktop, and drop that file into PhishHawk.',
  },
];

export const ON_A_PHONE = "Phone email apps can't save the email file. Open your email on a computer instead.";

export function GetTheEmail() {
  return (
    <Card className="p-6">
      <SectionTitle>How do I get the email?</SectionTitle>
      <p className="mt-2 text-sm leading-relaxed text-ink-dim">Check emails you received. Don&apos;t upload confidential work email.</p>
      <div className="mt-4 grid gap-2">
        {MAIL_APPS.map((mail) => (
          <details key={mail.app} className="rounded-2xl border border-line px-4 py-3">
            <summary className="cursor-pointer text-sm font-medium text-ink">
              {mail.app} ({mail.where})
            </summary>
            <ol className="mt-3 grid list-decimal gap-1.5 pl-5 text-sm leading-relaxed text-ink-dim">
              {mail.steps.map((step) => (
                <li key={step}>{step}</li>
              ))}
            </ol>
            <p className="mt-3 text-[13px] leading-relaxed text-ink-muted">{mail.after}</p>
          </details>
        ))}
      </div>
      <p className="mt-4 text-[13px] leading-relaxed text-ink-muted">On a phone? {ON_A_PHONE}</p>
    </Card>
  );
}
