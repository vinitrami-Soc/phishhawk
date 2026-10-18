/* Feedback for the people who run this server: a bug, an idea, a question or
   anything else. The page it is sent from goes with it, so they can see what
   was meant. Each person sends at most 10 an hour. */

import { useEffect, useId, useState, type FormEvent } from 'react';
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from '@/components/core/dialog';
import { sendFeedback } from '@/api/client';
import { ApiError, NETWORK_MESSAGE } from '@/api/errors';
import type { FeedbackKind } from '@/api/types';
import { sentence } from '@/components/phishhawk/AccountForm';
import { Button } from '@/components/ui/ui';
import { useToast } from '@/components/ui/toast';
import { cn } from '@/lib/utils';

export const FEEDBACK_KINDS: { id: FeedbackKind; label: string }[] = [
  { id: 'bug', label: 'Something is wrong' },
  { id: 'idea', label: 'An idea' },
  { id: 'question', label: 'A question' },
  { id: 'other', label: 'Something else' },
];
const MOST = 4000;

export function FeedbackDialog({ open, onOpenChange, onSent }: { open: boolean; onOpenChange: (o: boolean) => void; onSent?: () => void }) {
  const toast = useToast();
  const messageId = useId();
  const [kind, setKind] = useState<FeedbackKind>('bug');
  const [message, setMessage] = useState('');
  const [page, setPage] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (open) {
      setKind('bug');
      setMessage('');
      setError(null);
      setPage(window.location.pathname);
    }
  }, [open]);

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (!message.trim()) return setError('Write what you would like them to know.');
    setBusy(true);
    setError(null);
    try {
      await sendFeedback({ kind, message, page: page.startsWith('/app') ? page : '' });
      toast('Sent. Thank you.');
      onSent?.();
      onOpenChange(false);
    } catch (e) {
      if (!(e instanceof ApiError)) setError(NETWORK_MESSAGE);
      else if (e.status === 429) setError(`That is 10 this hour. Try again in ${Math.ceil((e.retryAfter ?? 60) / 60)} minutes.`);
      else setError(sentence(e.detail));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="w-[min(560px,calc(100vw-32px))] rounded-[24px] border border-line-strong bg-raised p-6 text-ink backdrop:bg-black/60">
        <DialogHeader>
          <DialogTitle className="text-lg font-semibold text-ink">Send feedback</DialogTitle>
          <DialogDescription className="text-sm text-ink-dim">
            It goes to the people who run this server, with the page you are on. Do not paste a message you are checking.
          </DialogDescription>
        </DialogHeader>
        <form className="mt-5 grid grid-cols-1 gap-4" onSubmit={submit} noValidate>
          <fieldset className="grid gap-2">
            <legend className="mb-1.5 text-[13px] font-medium text-ink-dim">What is it?</legend>
            <div className="flex flex-wrap gap-2">
              {FEEDBACK_KINDS.map((k) => (
                <label key={k.id} className={cn('cursor-pointer rounded-full border px-3.5 py-1.5 text-sm transition-colors', kind === k.id ? 'border-accent/50 bg-accent/10 font-medium text-ink' : 'border-line text-ink-dim hover:text-ink')}>
                  <input type="radio" name="feedback-kind" className="sr-only" checked={kind === k.id} onChange={() => setKind(k.id)} />
                  {k.label}
                </label>
              ))}
            </div>
          </fieldset>
          <div className="grid gap-1.5">
            <label htmlFor={messageId} className="text-[13px] font-medium text-ink-dim">
              Your message
            </label>
            <textarea
              id={messageId}
              rows={6}
              maxLength={MOST}
              value={message}
              onChange={(e) => setMessage(e.target.value)}
              className="block w-full resize-y rounded-[14px] border border-line-strong bg-surface px-3.5 py-3 text-sm leading-relaxed text-ink placeholder:text-ink-muted focus:border-accent/60 focus:outline-none"
            />
            <p className="flex flex-wrap justify-between gap-2 text-xs text-ink-muted">
              <span className="min-w-0 [overflow-wrap:anywhere]">{page.startsWith('/app') ? `Sent from ${page}` : 'Sent from no page in particular'}</span>
              <span className="tabular-nums">
                {message.length} / {MOST}
              </span>
            </p>
          </div>
          {error && (
            <p className="text-sm text-v-malicious" role="alert">
              {error}
            </p>
          )}
          <div className="mt-1 flex justify-end gap-2">
            <Button size="sm" variant="ghost" onClick={() => onOpenChange(false)} disabled={busy}>
              Cancel
            </Button>
            <Button size="sm" variant="primary" type="submit" disabled={busy}>
              Send
            </Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}
