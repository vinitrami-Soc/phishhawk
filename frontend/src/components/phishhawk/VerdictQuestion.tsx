/* "Was this verdict right?" on an analysis. Each person answers once and can
   change or withdraw the answer, with an optional note; everyone in the
   workspace sees the answers, and an admin can remove anyone's. A missed or
   false-alarm answer puts the analysis in the Queue's Disputed filter. */

import { useEffect, useId, useState } from 'react';
import { answerVerdict, getVerdictFeedback, withdrawVerdictAnswer } from '@/api/client';
import { ApiError, NETWORK_MESSAGE, isAbort } from '@/api/errors';
import type { Opinion, Session, VerdictFeedback } from '@/api/types';
import { sentence } from '@/components/phishhawk/AccountForm';
import { Button, Card, Time } from '@/components/ui/ui';
import { useToast } from '@/components/ui/toast';
import { cn } from '@/lib/utils';

export const OPINION_LABEL: Record<Opinion, string> = {
  right: 'Right',
  missed: 'It was phishing',
  false_alarm: 'It was not phishing',
};
const NOTE_MOST = 1000;

export function VerdictQuestion({ analysisId, session }: { analysisId: number; session: Session }) {
  const toast = useToast();
  const noteId = useId();
  const [state, setState] = useState<VerdictFeedback | null>(null);
  const [opinion, setOpinion] = useState<Opinion | null>(null);
  const [note, setNote] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    const controller = new AbortController();
    getVerdictFeedback(analysisId, controller.signal)
      .then((s) => {
        setState(s);
        setOpinion(s.mine?.opinion ?? null);
        setNote(s.mine?.note ?? '');
      })
      .catch((e) => !isAbort(e) && setError(e instanceof ApiError ? sentence(e.detail) : NETWORK_MESSAGE));
    return () => controller.abort();
  }, [analysisId, attempt]);

  async function act(action: () => Promise<unknown>, done: string) {
    setBusy(true);
    setError(null);
    try {
      await action();
      toast(done);
      setAttempt((a) => a + 1);
    } catch (e) {
      setError(e instanceof ApiError ? sentence(e.detail) : NETWORK_MESSAGE);
    } finally {
      setBusy(false);
    }
  }

  const mine = state?.mine ?? null;
  const changed = opinion !== null && (opinion !== mine?.opinion || note.trim() !== (mine?.note ?? ''));
  const others = state?.answers.filter((a) => a.user_id !== session.user_id) ?? [];
  const counts = state?.counts;
  const answered = counts ? counts.right + counts.missed + counts.false_alarm : 0;

  return (
    <Card className="grid gap-4 p-5 sm:p-6">
      <div className="flex flex-wrap items-start justify-between gap-x-6 gap-y-3">
        <div className="min-w-0">
          <h2 className="text-[15px] font-semibold tracking-tight text-ink">Was this verdict right?</h2>
          <p className="mt-1 text-[13px] text-ink-muted">
            {answered === 0
              ? 'No one has said yet. Your answer helps make PhishHawk better.'
              : `${answered} ${answered === 1 ? 'answer' : 'answers'}: ${counts!.right} right, ${counts!.missed} said it was phishing, ${counts!.false_alarm} said it was not.`}
          </p>
        </div>
        <div className="flex flex-wrap gap-2" role="radiogroup" aria-label="Was this verdict right?">
          {(Object.keys(OPINION_LABEL) as Opinion[]).map((o) => (
            <button
              key={o}
              type="button"
              role="radio"
              aria-checked={opinion === o}
              disabled={!state || busy}
              onClick={() => setOpinion(o)}
              className={cn(
                'rounded-full border px-3.5 py-1.5 text-sm transition-colors disabled:opacity-45',
                opinion === o ? 'border-accent/50 bg-accent/10 font-medium text-ink' : 'border-line text-ink-dim hover:text-ink',
              )}
            >
              {OPINION_LABEL[o]}
            </button>
          ))}
        </div>
      </div>

      {opinion !== null && (
        <div className="grid gap-3">
          <div className="grid gap-1.5">
            <label htmlFor={noteId} className="text-[13px] font-medium text-ink-dim">
              Note (optional)
            </label>
            <textarea
              id={noteId}
              rows={2}
              maxLength={NOTE_MOST}
              value={note}
              onChange={(e) => setNote(e.target.value)}
              placeholder={opinion === 'right' ? 'Anything worth knowing' : 'What gave it away, or why it is safe'}
              className="block w-full resize-y rounded-[14px] border border-line-strong bg-surface px-3.5 py-2.5 text-sm leading-relaxed text-ink placeholder:text-ink-muted focus:border-accent/60 focus:outline-none"
            />
          </div>
          <div className="flex flex-wrap items-center justify-end gap-2">
            {mine && (
              <Button size="sm" variant="ghost" className="mr-auto" disabled={busy} onClick={() => void act(() => withdrawVerdictAnswer(analysisId), 'Your answer was withdrawn.')}>
                Withdraw my answer
              </Button>
            )}
            <Button size="sm" variant="primary" disabled={busy || !changed} onClick={() => void act(() => answerVerdict(analysisId, { opinion, note }), mine ? 'Your answer was changed.' : 'Thank you. Your answer was saved.')}>
              {mine ? 'Save my answer' : 'Send my answer'}
            </Button>
          </div>
        </div>
      )}

      {error && (
        <p className="text-sm text-v-malicious" role="alert">
          {error}
        </p>
      )}

      {others.length > 0 && (
        <details className="group rounded-2xl border border-line bg-surface px-4 py-3">
          <summary className="cursor-pointer text-sm text-ink-dim">
            What others said ({others.length})
          </summary>
          <ul className="mt-3 grid gap-3">
            {others.map((a) => (
              <li key={a.id} className="flex flex-wrap items-start justify-between gap-3 text-sm">
                <div className="min-w-0">
                  <p className="text-ink">
                    <span className="font-medium">{a.username ?? 'Someone'}</span>: {OPINION_LABEL[a.opinion]}
                  </p>
                  {a.note && <p className="mt-0.5 whitespace-pre-wrap text-ink-dim [overflow-wrap:anywhere]">{a.note}</p>}
                  <p className="mt-0.5 text-xs text-ink-muted">
                    <Time iso={a.updated_at} />
                  </p>
                </div>
                {session.role === 'admin' && (
                  <Button size="sm" variant="ghost" disabled={busy} onClick={() => void act(() => withdrawVerdictAnswer(analysisId, a.id), 'The answer was removed.')}>
                    Remove
                  </Button>
                )}
              </li>
            ))}
          </ul>
        </details>
      )}
    </Card>
  );
}
