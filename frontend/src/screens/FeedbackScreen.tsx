/* Feedback (/app/feedback). Everyone sends feedback from here and sees what
   they sent; the server's owner sees everyone's, marks it done and can download
   every workspace's disputed verdicts. A workspace's admins also see how its
   verdicts were answered, with the disputed analyses. Everything here is shown
   as text, never as markup or a link it names. */

import { useEffect, useState } from 'react';
import { MessageSquarePlus } from 'lucide-react';
import { DISPUTED_CSV, deleteFeedback, getVerdictSummary, listFeedback, markFeedback } from '@/api/client';
import { ApiError, NETWORK_MESSAGE, isAbort } from '@/api/errors';
import type { Feedback, Session, VerdictSummary } from '@/api/types';
import { Link } from '@/app/router';
import { FEEDBACK_KINDS, FeedbackDialog } from '@/components/phishhawk/FeedbackDialog';
import { Button, Card, ConfirmDialog, EmptyState, ErrorState, PageHeader, SectionTitle, SkeletonRows, Time, VerdictBadge } from '@/components/ui/ui';
import { useToast } from '@/components/ui/toast';

const KIND_LABEL = Object.fromEntries(FEEDBACK_KINDS.map((k) => [k.id, k.label])) as Record<Feedback['kind'], string>;

function Verdicts({ owner }: { owner: boolean }) {
  const [summary, setSummary] = useState<VerdictSummary | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const controller = new AbortController();
    getVerdictSummary(controller.signal)
      .then(setSummary)
      .catch((e) => !isAbort(e) && setError(e instanceof ApiError ? e.detail : NETWORK_MESSAGE));
    return () => controller.abort();
  }, []);

  return (
    <section className="grid gap-3" aria-labelledby="verdicts-title">
      <div id="verdicts-title">
        <SectionTitle aside={summary ? `${summary.disputed.length} disputed` : undefined}>Answers on verdicts</SectionTitle>
      </div>
      {error ? (
        <p className="text-sm text-v-malicious" role="alert">
          {error}
        </p>
      ) : !summary ? (
        <SkeletonRows rows={2} />
      ) : (
        <Card className="grid gap-4 p-5">
          <p className="text-sm text-ink-dim">
            {summary.counts.right} right, {summary.counts.missed} said it was phishing, {summary.counts.false_alarm} said it was not.
          </p>
          {summary.disputed.length > 0 ? (
            <ul className="grid gap-2">
              {summary.disputed.map((d) => (
                <li key={d.analysis_id} className="flex flex-wrap items-center justify-between gap-3 rounded-2xl border border-line bg-surface px-4 py-3 text-sm">
                  <span className="flex min-w-0 flex-wrap items-center gap-2">
                    <VerdictBadge verdict={d.verdict} />
                    <Link href={`/app/analyses/${d.analysis_id}`} className="font-mono text-[13px] text-ink underline-offset-4 hover:underline">
                      {d.report_id}
                    </Link>
                  </span>
                  <span className="text-xs text-ink-muted">
                    {d.missed > 0 && `${d.missed} said it was phishing`}
                    {d.missed > 0 && d.false_alarm > 0 && ', '}
                    {d.false_alarm > 0 && `${d.false_alarm} said it was not`} · <Time iso={d.last_answer_at} />
                  </span>
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-sm text-ink-muted">No verdict is disputed.</p>
          )}
          <p className="text-xs text-ink-muted">
            The Queue&apos;s Disputed filter shows the same analyses.
            {owner && (
              <>
                {' '}
                <a href={DISPUTED_CSV} download className="font-medium text-accent underline-offset-4 hover:underline">
                  Download every workspace&apos;s disputed verdicts (CSV)
                </a>
                : report IDs, hashes, verdicts and counts, with no message, note or person.
              </>
            )}
          </p>
        </Card>
      )}
    </section>
  );
}

export default function FeedbackScreen({ session }: { session: Session }) {
  const toast = useToast();
  const [rows, setRows] = useState<Feedback[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [attempt, setAttempt] = useState(0);
  const [sending, setSending] = useState(false);
  const [removing, setRemoving] = useState<Feedback | null>(null);
  const [busy, setBusy] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);
  const owner = session.owner;

  useEffect(() => {
    const controller = new AbortController();
    setError(null);
    listFeedback(controller.signal)
      .then(setRows)
      .catch((e) => !isAbort(e) && setError(e instanceof ApiError ? e.detail : NETWORK_MESSAGE));
    return () => controller.abort();
  }, [attempt]);

  async function mark(row: Feedback) {
    try {
      const changed = await markFeedback(row.id, row.status === 'open' ? 'done' : 'open');
      setRows((list) => list?.map((f) => (f.id === changed.id ? changed : f)) ?? null);
    } catch (e) {
      toast(e instanceof ApiError ? e.detail : NETWORK_MESSAGE);
    }
  }

  async function remove() {
    if (!removing) return;
    setBusy(true);
    setActionError(null);
    try {
      await deleteFeedback(removing.id);
      setRows((list) => list?.filter((f) => f.id !== removing.id) ?? null);
      toast('Deleted.');
      setRemoving(null);
    } catch (e) {
      setActionError(e instanceof ApiError ? e.detail : NETWORK_MESSAGE);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="grid max-w-4xl grid-cols-1 gap-8">
      <PageHeader
        eyebrow="Feedback"
        title="Feedback"
        description={owner ? 'What everyone on this server sends you, newest first. Mark it done once it is dealt with.' : 'What you sent to the people who run this server, newest first.'}
        actions={
          <Button variant="primary" onClick={() => setSending(true)}>
            <MessageSquarePlus className="h-4 w-4" strokeWidth={1.75} /> Send feedback
          </Button>
        }
      />

      {session.role === 'admin' && <Verdicts owner={owner} />}

      <section className="grid gap-3" aria-labelledby="sent-title">
        <div id="sent-title">
          <SectionTitle aside={rows ? `${rows.filter((f) => f.status === 'open').length} open` : undefined}>{owner ? 'Everyone’s feedback' : 'What you sent'}</SectionTitle>
        </div>
        {error ? (
          <ErrorState detail={error} onRetry={() => setAttempt((a) => a + 1)} />
        ) : !rows ? (
          <SkeletonRows rows={3} />
        ) : !rows.length ? (
          <EmptyState title={owner ? 'No one has sent feedback yet.' : 'You have not sent any feedback yet.'} action={<Button onClick={() => setSending(true)}>Send feedback</Button>} />
        ) : (
          <Card className="divide-y divide-line overflow-hidden">
            {rows.map((f) => (
              <article key={f.id} className="grid gap-2 px-5 py-4">
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <p className="flex flex-wrap items-center gap-2 text-sm">
                    <span className="rounded-full border border-line px-2 py-0.5 text-[11px] font-medium text-ink-dim">{KIND_LABEL[f.kind] ?? f.kind}</span>
                    <span className={f.status === 'done' ? 'text-xs text-ok' : 'text-xs text-ink-muted'}>{f.status === 'done' ? 'Done' : 'Open'}</span>
                  </p>
                  <div className="flex flex-wrap gap-2">
                    {owner && (
                      <Button size="sm" variant="ghost" onClick={() => void mark(f)}>
                        {f.status === 'open' ? 'Mark done' : 'Reopen'}
                      </Button>
                    )}
                    <Button size="sm" variant="ghost" onClick={() => setRemoving(f)}>
                      Delete
                    </Button>
                  </div>
                </div>
                <p className="whitespace-pre-wrap text-sm text-ink [overflow-wrap:anywhere]">{f.message}</p>
                <p className="text-xs text-ink-muted [overflow-wrap:anywhere]">
                  {owner && `${f.username ?? 'Someone'} of ${f.workspace.name}, `}
                  <Time iso={f.created_at} />
                  {f.page && (
                    <>
                      {' '}
                      · from <span className="font-mono">{f.page}</span>
                    </>
                  )}
                </p>
              </article>
            ))}
          </Card>
        )}
      </section>

      <FeedbackDialog open={sending} onOpenChange={setSending} onSent={() => setAttempt((a) => a + 1)} />
      <ConfirmDialog
        open={removing !== null}
        onOpenChange={(open) => {
          if (!open) {
            setRemoving(null);
            setActionError(null);
          }
        }}
        title="Delete this feedback?"
        body="It is gone for everyone, its sender and the server's owner."
        confirmLabel="Delete"
        danger
        busy={busy}
        error={actionError}
        onConfirm={remove}
      />
    </div>
  );
}
