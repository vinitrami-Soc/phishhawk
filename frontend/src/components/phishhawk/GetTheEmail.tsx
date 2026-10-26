/* How someone on their own gets an email out of their mail app, for the simple
   upload page (docs/superpowers/specs/2026-10-26-simple-view-design.md, section 4).
   The menu names are each provider's; check them again when a provider changes
   its menus. */

import { Card, SectionTitle } from '@/components/ui/ui';

const APPS: { name: string; steps: string[]; after: string }[] = [
  {
    name: 'Gmail (on a computer)',
    steps: ['Open the email.', 'Click ⋮ (More), next to Reply.', 'Choose Download message.', 'Drop the downloaded file here.'],
    after: 'Or choose Show original instead, click Copy to clipboard, and paste it with Paste the message, above.',
  },
  {
    name: 'Outlook (Outlook.com or Outlook on the web)',
    steps: [
      'Open the email.',
      'Click … (More actions).',
      'Choose Download, then Download as EML. (Some versions say Save as, then Save as EML.)',
      'Drop the downloaded file here.',
    ],
    after:
      'A file saved from Outlook can leave out the hidden lines that show who really sent the email. PhishHawk still checks its links, attachments and wording.',
  },
  {
    name: 'Apple Mail (Mac)',
    steps: ['Select the email.', 'Choose File, then Save As.', 'Set Format to Raw Message Source, and save.', 'Drop the saved file here.'],
    after: 'Or drag the email from the list to your desktop, and drop that file here.',
  },
];

export function GetTheEmail() {
  return (
    <Card className="p-6">
      <SectionTitle>How do I get the email?</SectionTitle>
      <p className="mt-2 text-sm leading-relaxed text-ink-dim">Check emails you received. Don&apos;t upload confidential work email.</p>
      <div className="mt-4 grid gap-2">
        {APPS.map((app) => (
          <details key={app.name} className="rounded-2xl border border-line px-4 py-3">
            <summary className="cursor-pointer text-sm font-medium text-ink">{app.name}</summary>
            <ol className="mt-3 grid list-decimal gap-1.5 pl-5 text-sm leading-relaxed text-ink-dim">
              {app.steps.map((step) => (
                <li key={step}>{step}</li>
              ))}
            </ol>
            <p className="mt-3 text-[13px] leading-relaxed text-ink-muted">{app.after}</p>
          </details>
        ))}
      </div>
      <p className="mt-4 text-[13px] leading-relaxed text-ink-muted">
        On a phone? Phone email apps can&apos;t save the email file. Open your email on a computer instead.
      </p>
    </Card>
  );
}
