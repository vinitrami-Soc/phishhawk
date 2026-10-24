/* Privacy and terms: what this PhishHawk keeps, what leaves the server, the one
   cookie, and the terms of use. Readable before signing in. Every sentence here
   is what the M1 server does (docs/SERVER.md); change it only with the server. */

import { useEffect, useState, type ReactNode } from 'react';
import { getOperator } from '@/api/client';
import type { Operator } from '@/api/types';
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
  const [operator, setOperator] = useState<Operator | null>(null);

  useEffect(() => {
    const controller = new AbortController();
    getOperator(controller.signal)
      .then(setOperator)
      .catch(() => {}); // not known: the page reads as it does when nobody has said
    return () => controller.abort();
  }, []);

  return (
    <div className="grid max-w-3xl grid-cols-1 gap-6">
      <div className="pointer-events-none fixed inset-x-0 top-0 z-50 h-0.5 overflow-hidden print:hidden">
        <ScrollProgress className="absolute h-0.5 bg-accent" />
      </div>
      <PageHeader
        eyebrow="Privacy"
        title="Privacy and terms"
        description={
          <>
            What PhishHawk keeps, what leaves this server, and the one cookie it sets. Last updated <time dateTime="2026-10-24">24 October 2026</time>.
          </>
        }
      />

      <Section title="Who runs this PhishHawk">
        {operator?.name && (
          <p>
            This PhishHawk is run by <B>{operator.name}</B>.
            {operator.email && (
              <>
                {' '}
                For questions about your data, or to have it deleted, write to{' '}
                <a href={`mailto:${operator.email}`} className="text-ink underline underline-offset-2 hover:text-accent">
                  {operator.email}
                </a>
                .
              </>
            )}
          </p>
        )}
        <p>
          Whoever set up this server runs it: its owner. The owner decides whether anyone may create an account. Each organisation, and each person on their own, has a workspace of its own,
          and no one sees another workspace&apos;s messages, analyses or people. A workspace&apos;s admins decide who is in it and how long its messages are kept, and its own policies apply to
          what you submit. For questions about your data, ask an admin of your workspace.
        </p>
      </Section>

      <Section title="What PhishHawk keeps">
        <ul className="grid list-disc gap-2.5 pl-5 marker:text-ink-muted">
          <li>
            <B>Your account</B>: your username, your role, when you last signed in, and a hash of your password. The password itself is never stored. API tokens, for scripts, are kept
            only as a hash and shown once, when they are created.
          </li>
          <li>
            <B>Your profile</B>: your first and last name, location and job title, so the people you work with know who you are. Only the people in your workspace see it; the server&apos;s
            owner sees each workspace&apos;s name and how many people are in it, never their profiles.
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
            <B>Your feedback</B>: what you send the server&apos;s owner, with its kind and the page you sent it from, read only by you and the owner; and your answers on whether a
            verdict was right, with any note, seen by everyone in your workspace. The owner&apos;s download of disputed verdicts names no person and holds no message or note.
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

      <Section title="Deleting your account">
        <ul className="grid list-disc gap-2.5 pl-5 marker:text-ink-muted">
          <li>On your own, you delete your account on your Profile page, with your password. Your workspace goes with it, with everything in it, for good.</li>
          <li>
            In an organisation, its admins delete accounts. The messages someone submitted stay with the organisation; their account, profile, API tokens, feedback and answers on verdicts
            go.
          </li>
          <li>The server&apos;s owner can delete a whole workspace, with everything in it.</li>
          <li>The audit log keeps its records, with the username of whoever did each thing: it is the record of what was done, and it cannot be changed.</li>
        </ul>
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
