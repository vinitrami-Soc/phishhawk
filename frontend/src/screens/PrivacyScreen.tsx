/* Privacy and terms: what this PhishHawk keeps, what leaves the server, the one
   cookie, and the terms of use. Readable before signing in. Every sentence here
   is what the M1 server does (docs/SERVER.md); change it only with the server. */

import type { ReactNode } from 'react';
import { ScrollProgress } from '@/components/core/scroll-progress';
import { Link } from '@/app/router';
import { Card, PageHeader } from '@/components/ui/ui';

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <Card className="grid gap-3 p-6 text-sm leading-relaxed text-ink-dim sm:p-7">
      <h2 className="text-lg font-semibold tracking-tight text-ink">{title}</h2>
      {children}
    </Card>
  );
}

const B = ({ children }: { children: ReactNode }) => <strong className="font-medium text-ink">{children}</strong>;

export default function PrivacyScreen() {
  return (
    <div className="grid max-w-3xl grid-cols-1 gap-6">
      <ScrollProgress className="fixed z-50 h-0.5 bg-accent print:hidden" />
      <PageHeader
        eyebrow="Privacy"
        title="Privacy and terms"
        description={
          <>
            What PhishHawk keeps, what leaves this server, and the one cookie it sets. Last updated <time dateTime="2026-10-12">12 October 2026</time>.
          </>
        }
      />

      <Section title="Who runs this PhishHawk">
        <p>
          Your organisation runs PhishHawk on its own server, for its security team. It decides who has an account and how long messages are kept, and its own policies apply to what you
          submit. For questions about your data, or to have something deleted, ask your PhishHawk admin.
        </p>
      </Section>

      <Section title="What PhishHawk keeps">
        <ul className="grid list-disc gap-2.5 pl-5 marker:text-ink-muted">
          <li>
            <B>Your account</B>: your username, your role, when you last signed in, and a hash of your password. The password itself is never stored. API tokens, for scripts, are kept
            only as a hash and shown once, when they are created.
          </li>
          <li>
            <B>Your session</B>, while you are signed in. It ends when you sign out, or after eight hours without use (your admin can change this).
          </li>
          <li>
            <B>Each message you submit</B>, in two parts.
            <ul className="mt-2 grid list-[circle] gap-2 pl-5">
              <li>
                The message, its full report and its six export files, encrypted on the server. They are deleted after the retention period (30 days unless your admin changed it), or at
                once with Delete now. A message on hold is kept until an admin releases it.
              </li>
              <li>
                A summary: the message&apos;s SHA-256 and size, the verdict and score, the report ID, the sender&apos;s address and domain, the number of recipients, the indicators found and
                the ATT&amp;CK techniques. The subject and the sender&apos;s display name are kept only as keyed hashes, to match campaigns, and cannot be read back. The summary stays until an
                admin uses Delete completely. Recipient addresses, the subject in clear, the body and attachment names are never part of it.
              </li>
            </ul>
          </li>
          <li>
            <B>The audit log</B>: every sign-in and failed sign-in, submission, analysis, download, re-analysis, deletion, hold, settings change and user or token change, with who did it
            and when. Each record is chained to the one before, so a changed or removed record is detected. It is not deleted with messages.
          </li>
          <li>
            <B>The server&apos;s log</B>: the address each request came from, its method, path and status, never its content. Your admin decides how long it is kept. Your address is also
            used, in memory only, to slow down repeated failed sign-ins.
          </li>
        </ul>
      </Section>

      <Section title="What leaves this server">
        <p>
          Nothing, on a new installation. An admin can turn on reputation providers: VirusTotal, urlscan.io, AbuseIPDB and RDAP. PhishHawk then looks up indicators from the message with
          them, such as links, domains and IP addresses. It never sends them the message itself.
        </p>
        <p>
          To send nothing for one message, turn on Offline analysis when you submit it. Each analysis records which providers were asked.
        </p>
      </Section>

      <Section title="Cookies and storage on your device">
        <p>
          PhishHawk sets one cookie when you sign in, only to keep you signed in. Scripts cannot read it, it goes only to this server, and it is removed when you sign out.
        </p>
        <p>
          If you use the light and dark switch, your choice is kept in this browser&apos;s storage. Nothing else is stored on your device. There are no analytics, advertising or tracking
          cookies, and the app loads nothing from other sites.
        </p>
      </Section>

      <Section title="Terms of use">
        <ul className="grid list-disc gap-2.5 pl-5 marker:text-ink-muted">
          <li>PhishHawk is for your organisation&apos;s security work. Submit only messages you are allowed to handle under your organisation&apos;s policies.</li>
          <li>Treat reports, indicators and exports as confidential: they can hold personal data from the reported message.</li>
          <li>A verdict comes from automated checks and can be wrong. Check the evidence before you act on it.</li>
          <li>PhishHawk is open-source software under the MIT licence and comes without warranty.</li>
        </ul>
      </Section>

      <p className="text-[13px] text-ink-muted">
        More about how PhishHawk works is in{' '}
        <Link href="/app/help" className="text-ink underline underline-offset-2 hover:text-accent">
          Help
        </Link>
        .
      </p>
    </div>
  );
}
