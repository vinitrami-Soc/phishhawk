/* Help: common questions, each one opening in place, how to get an email out
   of a mail app, and what PhishHawk is. Readable before signing in, and the
   page search engines may list. The answers describe what the server and the
   engine do; change them only with the code. */

import { ScrollProgress } from '@/components/core/scroll-progress';
import { MAIL_APPS, ON_A_PHONE } from '@/components/phishhawk/GetTheEmail';
import { Question } from '@/components/phishhawk/Question';
import { Link } from '@/app/router';
import { VERDICT_MEANING } from '@/app/vocabulary';
import { Card, PageHeader, VerdictBadge } from '@/components/ui/ui';

export default function HelpScreen() {
  return (
    <div className="grid max-w-3xl grid-cols-1 gap-6">
      <div className="pointer-events-none fixed inset-x-0 top-0 z-50 h-0.5 overflow-hidden print:hidden">
        <ScrollProgress className="absolute h-0.5 bg-accent" />
      </div>
      <PageHeader eyebrow="Help" title="Help" description="Answers to common questions about PhishHawk. For anything else, ask your PhishHawk admin." />

      <Card className="overflow-hidden">
        <Question question="What do the verdicts mean?">
          <ul className="grid gap-3">
            {VERDICT_MEANING.map(([verdict, meaning]) => (
              <li key={verdict} className="grid gap-1.5 sm:grid-cols-[210px_1fr] sm:items-start sm:gap-4">
                <span>
                  <VerdictBadge verdict={verdict} />
                </span>
                <span>{meaning}</span>
              </li>
            ))}
          </ul>
          <p>The Overview tab of each analysis lists the signals behind its verdict, and why each one matters.</p>
        </Question>
        <Question question="What does Offline analysis do?">
          <p>
            Nothing from the message is sent to reputation providers: the analysis uses only what is in the message. Use it for sensitive mail. If an admin has not turned on any provider,
            every analysis is offline anyway.
          </p>
        </Question>
        <Question question="Which files can I submit?">
          <p>
            One or more .eml or .msg files, an .mbox or a .zip, or the full message pasted with its headers. Several messages are analysed together as a batch. Each message can be up
            to 25 MB, a whole upload four times that, and a batch up to 500 messages; your admin can change these limits.
          </p>
        </Question>
        <Question question="Is it safe to open the links in a report?">
          <p>
            Links and addresses are shown defanged (hxxp, [.]) so they cannot be opened by mistake. The HTML report opens in a sandbox, where nothing from the reported message can run in
            PhishHawk or reach your session. Do not visit the links themselves from your work computer.
          </p>
        </Question>
        <Question question="Who can see what?">
          <p>
            Everyone who can sign in sees every analysis and can download its reports. The original message can be downloaded by the analyst who submitted it and by admins. Analysts see
            their own entries in the audit log; admins see all of it, and also Health, Settings, Users and API tokens.
          </p>
        </Question>
        <Question question="How long is a message kept, and how do I delete it?">
          <p>
            The message and its reports are deleted after the retention period: 30 days unless your admin changed it. Delete now removes them at once (the analyst who submitted the message,
            or an admin). Hold keeps them past the retention period until an admin releases it. Delete completely (admins only) also removes the summary. See{' '}
            <Link href="/app/privacy" className="text-ink underline underline-offset-2 hover:text-accent">
              Privacy and terms
            </Link>{' '}
            for what the summary holds.
          </p>
        </Question>
        <Question question="I cannot sign in.">
          <p>
            If this server sends email, choose Forgot password? on the sign-in page. Otherwise ask your PhishHawk admin, who manages the accounts. After several wrong tries, each new
            try has to wait a little longer.
          </p>
        </Question>
      </Card>

      <Card className="grid gap-6 p-6 text-sm leading-relaxed text-ink-dim sm:p-7">
        <div className="grid gap-2">
          <h2 className="text-lg font-semibold tracking-tight text-ink">Get the email out of your mail app</h2>
          <p>
            PhishHawk checks the whole email, with the hidden lines at its top that show who really sent it. Save it as an .eml file, or copy all of it, and give it to PhishHawk.
          </p>
        </div>
        {MAIL_APPS.map((mail) => (
          <section key={mail.app} className="grid gap-2">
            <h3 className="text-[15px] font-semibold tracking-tight text-ink">Download an email as .eml from {mail.app}</h3>
            <p className="text-[13px] text-ink-muted">{mail.where[0].toUpperCase() + mail.where.slice(1)}</p>
            <ol className="grid list-decimal gap-1 pl-5">
              {mail.steps.map((step) => (
                <li key={step}>{step}</li>
              ))}
            </ol>
            <p className="text-[13px] text-ink-muted">{mail.after}</p>
          </section>
        ))}
        <section className="grid gap-2">
          <h3 className="text-[15px] font-semibold tracking-tight text-ink">Download an email as .eml on a phone</h3>
          <p>{ON_A_PHONE}</p>
        </section>
      </Card>

      <Card className="grid gap-3 p-6 text-sm leading-relaxed text-ink-dim sm:p-7">
        <h2 className="text-lg font-semibold tracking-tight text-ink">About PhishHawk</h2>
        <p>
          PhishHawk analyses reported phishing email on a server your organisation runs: it reads the message, checks its headers, links, attachments and QR codes, and gives a verdict with
          the evidence, a full HTML report and exports for other tools. It is open-source software under the MIT licence.
        </p>
      </Card>
    </div>
  );
}
