/* Invitations, on Users (an organization's admins). An invitation is a link
   that lets one person make their own account in the organization, with the
   role chosen here. It works once, for 7 days. The link is shown once, right
   after it is made: the server keeps only a hash of it. Pending invitations
   can be withdrawn. */

import { useEffect, useState, type FormEvent } from 'react';
import { Link2 } from 'lucide-react';
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from '@/components/core/dialog';
import { createInvite, inviteLink, listInvites, revokeInvite } from '@/api/client';
import { ApiError, NETWORK_MESSAGE, isAbort } from '@/api/errors';
import type { Invite, Role } from '@/api/types';
import { ROLE_LABEL } from '@/app/vocabulary';
import { Button, Card, ConfirmDialog, CopyButton, SectionTitle, SkeletonRows, TextField, Time } from '@/components/ui/ui';
import { useToast } from '@/components/ui/toast';
import { cn } from '@/lib/utils';

function InviteDialog({ open, onOpenChange, onMade }: { open: boolean; onOpenChange: (o: boolean) => void; onMade: (invite: Invite) => void }) {
  const [role, setRole] = useState<Role>('analyst');
  const [note, setNote] = useState('');
  const [link, setLink] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (open) {
      setRole('analyst');
      setNote('');
      setLink(null);
      setError(null);
    }
  }, [open]);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const { token, link: _serverLink, ...made } = await createInvite({ role, note: note.trim() });
      setLink(inviteLink(token));
      onMade(made);
    } catch (e) {
      setError(e instanceof ApiError ? e.detail : NETWORK_MESSAGE);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="w-[min(500px,calc(100vw-32px))] rounded-[24px] border border-line-strong bg-raised p-6 text-ink backdrop:bg-black/60">
        <DialogHeader>
          <DialogTitle className="text-lg font-semibold text-ink">{link ? 'Send this link' : 'Invite someone'}</DialogTitle>
          <DialogDescription className="text-sm text-ink-dim">
            {link
              ? 'Copy it now: it is shown only once. Send it however you like. It works once, for 7 days.'
              : 'They make their own account with the link, and join with the role you choose.'}
          </DialogDescription>
        </DialogHeader>
        {link ? (
          <div className="mt-5 grid grid-cols-1 gap-4">
            <code className="block break-all rounded-2xl border border-line bg-sunken px-4 py-3 font-mono text-[13px] text-ink">{link}</code>
            <div className="flex items-center justify-end gap-2">
              <CopyButton text={link} label="Copy the invitation link" />
              <Button size="sm" variant="primary" onClick={() => onOpenChange(false)}>
                Done
              </Button>
            </div>
          </div>
        ) : (
          <form className="mt-5 grid gap-4" onSubmit={submit} noValidate>
            <fieldset className="grid gap-2">
              <legend className="mb-1.5 text-[13px] font-medium text-ink-dim">Role</legend>
              {(['analyst', 'admin'] as const).map((r) => (
                <label key={r} className={cn('flex cursor-pointer items-start gap-3 rounded-2xl border px-4 py-3 text-sm', role === r ? 'border-accent/50 bg-accent/5' : 'border-line')}>
                  <input type="radio" name="invite-role" checked={role === r} onChange={() => setRole(r)} className="mt-0.5 accent-[var(--accent)]" />
                  <span>
                    <span className="block font-medium text-ink">{ROLE_LABEL[r]}</span>
                    <span className="block text-xs text-ink-muted">{r === 'admin' ? 'Everything, including settings, users and invitations.' : 'Analyses, the queue and their own audit entries.'}</span>
                  </span>
                </label>
              ))}
            </fieldset>
            <TextField label="Note (optional)" maxLength={120} value={note} onChange={(e) => setNote(e.target.value)} hint='For you: who it is for, such as "Priya, SOC team".' />
            {error && (
              <p className="text-sm text-v-malicious" role="alert">
                {error}
              </p>
            )}
            <div className="mt-2 flex justify-end gap-2">
              <Button size="sm" variant="ghost" onClick={() => onOpenChange(false)} disabled={busy}>
                Cancel
              </Button>
              <Button size="sm" variant="primary" type="submit" disabled={busy}>
                Make the link
              </Button>
            </div>
          </form>
        )}
      </DialogContent>
    </Dialog>
  );
}

/** The organization's pending invitations, with Invite and Withdraw. `inviting` opens the dialog from outside. */
export function Invitations({ inviting, onInvitingChange }: { inviting: boolean; onInvitingChange: (open: boolean) => void }) {
  const toast = useToast();
  const [invites, setInvites] = useState<Invite[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [withdraw, setWithdraw] = useState<Invite | null>(null);
  const [busy, setBusy] = useState(false);
  const [withdrawError, setWithdrawError] = useState<string | null>(null);

  useEffect(() => {
    const controller = new AbortController();
    listInvites(controller.signal)
      .then(setInvites)
      .catch((e) => !isAbort(e) && setError(e instanceof ApiError ? e.detail : NETWORK_MESSAGE));
    return () => controller.abort();
  }, []);

  async function confirmWithdraw() {
    if (!withdraw) return;
    setBusy(true);
    setWithdrawError(null);
    try {
      await revokeInvite(withdraw.id);
      setInvites((list) => list?.filter((i) => i.id !== withdraw.id) ?? null);
      toast('Invitation withdrawn.');
      setWithdraw(null);
    } catch (e) {
      setWithdrawError(e instanceof ApiError ? e.detail : NETWORK_MESSAGE);
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="grid gap-3" aria-labelledby="invitations-title">
      <div id="invitations-title">
        <SectionTitle aside={invites ? `${invites.length} waiting` : undefined}>Invitations</SectionTitle>
      </div>
      {error ? (
        <p className="text-sm text-v-malicious" role="alert">
          {error}
        </p>
      ) : !invites ? (
        <SkeletonRows rows={2} />
      ) : !invites.length ? (
        <Card className="flex flex-wrap items-center justify-between gap-3 px-5 py-4">
          <p className="text-sm text-ink-dim">No invitation is waiting. Invite someone, and they make their own account.</p>
          <Button size="sm" onClick={() => onInvitingChange(true)}>
            <Link2 className="h-4 w-4" strokeWidth={1.75} /> Invite
          </Button>
        </Card>
      ) : (
        <Card className="divide-y divide-line overflow-hidden">
          {invites.map((i) => (
            <div key={i.id} className="flex flex-wrap items-center justify-between gap-4 px-5 py-4">
              <div className="min-w-0">
                <p className="flex flex-wrap items-center gap-2 text-sm font-medium text-ink [overflow-wrap:anywhere]">
                  {i.note || 'Invitation'}
                  <span className="rounded-full border border-line px-2 py-0.5 text-[11px] font-medium text-ink-dim">{ROLE_LABEL[i.role]}</span>
                </p>
                <p className="mt-0.5 text-xs text-ink-muted">
                  By {i.created_by_name ?? 'an admin'}, works until <Time iso={i.expires_at} />
                </p>
              </div>
              <Button size="sm" variant="danger" onClick={() => setWithdraw(i)}>
                Withdraw
              </Button>
            </div>
          ))}
        </Card>
      )}

      <InviteDialog open={inviting} onOpenChange={onInvitingChange} onMade={(made) => setInvites((list) => [...(list ?? []), made])} />
      <ConfirmDialog
        open={withdraw !== null}
        onOpenChange={(open) => {
          if (!open) {
            setWithdraw(null);
            setWithdrawError(null);
          }
        }}
        title="Withdraw this invitation?"
        body="The link stops working. Anyone who already joined with it stays."
        confirmLabel="Withdraw"
        danger
        busy={busy}
        error={withdrawError}
        onConfirm={confirmWithdraw}
      />
    </section>
  );
}
