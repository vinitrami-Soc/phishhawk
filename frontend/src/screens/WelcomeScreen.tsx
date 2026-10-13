/* The setup after sign-up, opened once. An organization's admin invites the
   team, connects a report mailbox and chooses reputation providers; someone on
   their own chooses providers; everyone gets a short tour. Each step can be
   skipped, and so can all of it. Finishing or skipping tells the server, so the
   console stops opening it; /app/welcome still shows it to anyone who wants it. */

import { useEffect, useState, type FormEvent, type ReactNode } from 'react';
import { Check } from 'lucide-react';
import { createInvite, finishOnboarding, getSettings, inviteLink, listAnalyses, patchSettings } from '@/api/client';
import { ApiError, NETWORK_MESSAGE, isAbort } from '@/api/errors';
import type { Mailbox, Role, Session, Settings } from '@/api/types';
import { onboardingSteps, type OnboardingStep } from '@/app/permissions';
import { Link } from '@/app/router';
import { ROLE_LABEL } from '@/app/vocabulary';
import { ProviderFields, typedKeys } from '@/components/phishhawk/ProviderFields';
import { Button, Card, CopyButton, PageHeader, SectionTitle, Skeleton, TextField } from '@/components/ui/ui';
import { cn } from '@/lib/utils';
import { MailboxDialog } from '@/screens/MailboxesScreen';

const STEP_NAME: Record<OnboardingStep, string> = {
  invite: 'Invite your team',
  mailbox: 'Connect a report mailbox',
  providers: 'Reputation providers',
  tour: 'A look around',
};

/** One step: what it is for, its content, and Back / Skip / Next under it. */
function Step({ step, intro, children, actions }: { step: OnboardingStep; intro: ReactNode; children?: ReactNode; actions: ReactNode }) {
  return (
    <Card className="grid gap-5 p-5 sm:p-7">
      <div>
        <SectionTitle>{STEP_NAME[step]}</SectionTitle>
        <p className="mt-1 max-w-[65ch] text-[13px] text-ink-muted">{intro}</p>
      </div>
      {children}
      <div className="flex flex-wrap items-center justify-end gap-2">{actions}</div>
    </Card>
  );
}

type Made = { note: string; role: Role; link: string };

function InviteStep({ organization, actions }: { organization: string; actions: (made: boolean) => ReactNode }) {
  const [role, setRole] = useState<Role>('analyst');
  const [note, setNote] = useState('');
  const [made, setMade] = useState<Made[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const invite = await createInvite({ role, note: note.trim() });
      setMade((list) => [...list, { note: invite.note, role: invite.role, link: inviteLink(invite.token) }]);
      setNote('');
    } catch (e) {
      setError(e instanceof ApiError ? e.detail : NETWORK_MESSAGE);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Step
      step="invite"
      intro={`Each link lets one person make their own account in ${organization}, with the role you choose. It works once, for 7 days, and is shown only here: copy it now.`}
      actions={actions(made.length > 0)}
    >
      <form className="grid grid-cols-1 items-end gap-3 sm:grid-cols-[minmax(0,1fr)_auto_auto]" onSubmit={submit} noValidate>
        <TextField label="Who it is for (optional)" maxLength={120} value={note} onChange={(e) => setNote(e.target.value)} placeholder="Priya, SOC team" />
        <fieldset className="grid gap-1.5">
          <legend className="mb-1.5 text-[13px] font-medium text-ink-dim">Role</legend>
          <div className="flex h-11 rounded-[14px] border border-line-strong bg-raised p-1">
            {(['analyst', 'admin'] as const).map((r) => (
              <label key={r} className={cn('flex cursor-pointer items-center rounded-[10px] px-3 text-sm', role === r ? 'bg-accent/10 font-medium text-ink' : 'text-ink-dim')}>
                <input type="radio" name="onboarding-role" className="sr-only" checked={role === r} onChange={() => setRole(r)} />
                {ROLE_LABEL[r]}
              </label>
            ))}
          </div>
        </fieldset>
        <Button type="submit" disabled={busy} className="h-11">
          Make a link
        </Button>
      </form>
      {error && (
        <p className="text-sm text-v-malicious" role="alert">
          {error}
        </p>
      )}
      {made.length > 0 && (
        <ul className="grid gap-3" aria-label="Links made">
          {made.map((m) => (
            <li key={m.link} className="grid gap-2 rounded-2xl border border-line bg-surface p-3">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <span className="text-sm font-medium text-ink [overflow-wrap:anywhere]">
                  {m.note || 'Invitation'} · {ROLE_LABEL[m.role]}
                </span>
                <CopyButton text={m.link} label="Copy the invitation link" />
              </div>
              <code className="block break-all font-mono text-[13px] text-ink-dim">{m.link}</code>
            </li>
          ))}
        </ul>
      )}
    </Step>
  );
}

function MailboxStep({ actions }: { actions: (made: boolean) => ReactNode }) {
  const [open, setOpen] = useState(false);
  const [added, setAdded] = useState<Mailbox[]>([]);
  return (
    <Step
      step="mailbox"
      intro="PhishHawk reads the mailbox your people forward suspicious mail to, and analyses each report. It only reads: it never sends, moves or deletes mail. You can add more on Mailboxes, in More."
      actions={actions(added.length > 0)}
    >
      {added.map((m) => (
        <p key={m.id} className="flex items-center gap-2 text-sm text-ink">
          <Check className="h-4 w-4 text-ok" strokeWidth={2} aria-hidden="true" />
          {m.name} is connected. The first poll imports its newest 50 messages.
        </p>
      ))}
      <div>
        <Button onClick={() => setOpen(true)}>{added.length ? 'Connect another mailbox' : 'Connect a mailbox'}</Button>
      </div>
      <MailboxDialog open={open} onOpenChange={setOpen} editing={null} onSaved={(m) => setAdded((list) => [...list, m])} />
    </Step>
  );
}

function ProvidersStep({ onNext, back }: { onNext: () => void; back: ReactNode }) {
  const [settings, setSettings] = useState<Settings | null>(null);
  const [providers, setProviders] = useState<string[]>([]);
  const [keys, setKeys] = useState<Record<string, string>>({});
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    const controller = new AbortController();
    getSettings(controller.signal)
      .then((s) => {
        setSettings(s);
        setProviders(s.providers);
      })
      .catch((e) => !isAbort(e) && setError(e instanceof ApiError ? e.detail : NETWORK_MESSAGE));
    return () => controller.abort();
  }, []);

  async function save() {
    setBusy(true);
    setError(null);
    try {
      const typed = typedKeys(keys);
      await patchSettings({ providers, ...(Object.keys(typed).length ? { keys: typed } : {}) });
      onNext();
    } catch (e) {
      setError(e instanceof ApiError ? e.detail : NETWORK_MESSAGE);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Step
      step="providers"
      intro="Optional: PhishHawk works offline without any of them. When one is on, PhishHawk sends it the message's indicators (links, domains, addresses and file hashes), never the email itself. They stay in Settings."
      actions={
        <>
          {back}
          <Button variant="ghost" onClick={onNext}>
            Skip
          </Button>
          <Button variant="primary" onClick={() => void save()} disabled={busy || !settings}>
            Save and continue
          </Button>
        </>
      }
    >
      {settings ? <ProviderFields saved={settings.keys} providers={providers} onProvidersChange={setProviders} keys={keys} onKeysChange={setKeys} /> : !error && <Skeleton className="h-72 rounded-[20px]" />}
      {error && (
        <p className="text-sm text-v-malicious" role="alert">
          {error}
        </p>
      )}
    </Step>
  );
}

function TourStep({ workspace, onShow, actions }: { workspace: string; onShow: (href: string) => void; actions: ReactNode }) {
  const [newest, setNewest] = useState<number | null>(null);
  useEffect(() => {
    const controller = new AbortController();
    listAnalyses({}, controller.signal)
      .then((list) => setNewest(list[0]?.id ?? null))
      .catch(() => undefined); // without one, the card leads to Triage
    return () => controller.abort();
  }, []);

  const cards = [
    { title: 'Triage', text: 'Paste a message, or upload .eml, .msg, .mbox or .zip files, and get a verdict in seconds.', href: '/app/' },
    { title: 'Queue', text: `Every analysis in ${workspace}, newest first, filtered by verdict, source and who sent it.`, href: '/app/analyses' },
    { title: 'An analysis', text: 'Each one explains its verdict: the findings, the links and files, and what to do next.', href: newest ? `/app/analyses/${newest}` : '/app/' },
    { title: 'Campaigns', text: 'Messages that share senders, links or files are grouped, so one report shows the whole campaign.', href: '/app/campaigns' },
    { title: 'Audit', text: 'Who did what, and when, in a log that shows whether anything in it was changed.', href: '/app/audit' },
  ];
  return (
    <Step step="tour" intro="Five places to know. Each opens from the top bar." actions={actions}>
      <ul className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
        {cards.map((c) => (
          <li key={c.title} className="flex flex-col gap-3 rounded-[20px] border border-line bg-raised p-5">
            <h3 className="text-sm font-semibold text-ink">{c.title}</h3>
            <p className="flex-1 text-[13px] text-ink-dim">{c.text}</p>
            <Link
              href={c.href}
              onClick={(event) => {
                event.preventDefault();
                onShow(c.href);
              }}
              className="w-max text-sm font-medium text-accent underline-offset-4 hover:underline"
            >
              Show me<span className="sr-only"> {c.title}</span>
            </Link>
          </li>
        ))}
      </ul>
    </Step>
  );
}

export default function WelcomeScreen({ session, onDone }: { session: Session; onDone: (href: string) => void }) {
  const steps = onboardingSteps(session);
  const [index, setIndex] = useState(0);
  const [finishing, setFinishing] = useState(false);
  const step = steps[Math.min(index, steps.length - 1)];
  const workspace = session.workspace?.name ?? 'your workspace';
  const name = session.profile?.first_name || session.username;

  /** Tells the server it is done (a failure only means it opens again next time), then leaves. */
  async function finish(href = '/app/') {
    if (finishing) return;
    setFinishing(true);
    try {
      await finishOnboarding();
    } catch {
      // the console opens the setup again after the next sign-in; nothing else depends on it
    }
    onDone(href);
  }

  const next = () => setIndex((i) => Math.min(i + 1, steps.length - 1));
  const back = index > 0 && (
    <Button variant="ghost" className="mr-auto" onClick={() => setIndex((i) => i - 1)}>
      Back
    </Button>
  );
  const moveOn = (made: boolean) => (
    <>
      {back}
      {made ? (
        <Button variant="primary" onClick={next}>
          Next
        </Button>
      ) : (
        <Button variant="ghost" onClick={next}>
          Skip
        </Button>
      )}
    </>
  );

  return (
    <div className="grid max-w-5xl grid-cols-1 gap-6">
      <PageHeader
        eyebrow="Welcome"
        title={`Welcome, ${name}`}
        description={
          steps.length > 1
            ? `${steps.length} short steps to get ${workspace} going. Skip any of them: all of it stays in the console.`
            : `A short look around ${workspace}.`
        }
        actions={
          <Button variant="ghost" onClick={() => void finish()} disabled={finishing}>
            Skip setup
          </Button>
        }
      />
      {steps.length > 1 && (
        <ol aria-label="Setup steps" className="flex flex-wrap gap-2">
          {steps.map((s, i) => (
            <li key={s} aria-current={s === step ? 'step' : undefined} className={cn('rounded-full border px-3 py-1 text-xs', s === step ? 'border-accent/50 bg-accent/10 font-medium text-ink' : i < index ? 'border-line text-ink-dim' : 'border-line text-ink-muted')}>
              {i + 1}. {STEP_NAME[s]}
            </li>
          ))}
        </ol>
      )}
      {step === 'invite' && <InviteStep organization={workspace} actions={moveOn} />}
      {step === 'mailbox' && <MailboxStep actions={moveOn} />}
      {step === 'providers' && <ProvidersStep onNext={next} back={back} />}
      {step === 'tour' && (
        <TourStep
          workspace={workspace}
          onShow={(href) => void finish(href)}
          actions={
            <>
              {back}
              <Button variant="primary" onClick={() => void finish()} disabled={finishing}>
                Finish
              </Button>
            </>
          }
        />
      )}
    </div>
  );
}
