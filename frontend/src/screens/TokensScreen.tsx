/* API tokens (admin). A new token is shown once and never kept. */

import { useEffect, useState, type FormEvent } from 'react';
import { KeyRound } from 'lucide-react';
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from '@/components/core/dialog';
import { createToken, listTokens, listUsers, revokeToken } from '@/api/client';
import { ApiError, NETWORK_MESSAGE, isAbort } from '@/api/errors';
import type { NewToken, Token, User } from '@/api/types';
import { Button, Card, ConfirmDialog, CopyButton, EmptyState, ErrorState, PageHeader, SkeletonRows, TextField, Time } from '@/components/ui/ui';
import { useToast } from '@/components/ui/toast';
import { cn } from '@/lib/utils';

const SCOPES = [
  { id: 'read', label: 'Read', text: 'View analyses and reports.' },
  { id: 'submit', label: 'Submit', text: 'Send messages for analysis.' },
] as const;

function CreateTokenDialog({ open, onOpenChange, users, onCreated }: { open: boolean; onOpenChange: (o: boolean) => void; users: User[]; onCreated: () => void }) {
  const [name, setName] = useState('');
  const [userId, setUserId] = useState<number>(users[0]?.id ?? 0);
  const [scope, setScope] = useState<'read' | 'submit'>('read');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [created, setCreated] = useState<NewToken | null>(null);

  useEffect(() => {
    if (open) {
      setName('');
      setScope('read');
      setUserId(users[0]?.id ?? 0);
      setError(null);
      setCreated(null);
    } else {
      setCreated(null); // never keep a token after the dialog closes
    }
    // reset only when the dialog opens or closes, not when the user list refreshes
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (!name.trim() || name.trim().length > 64) return setError('Give the token a name of 1 to 64 characters.');
    setBusy(true);
    setError(null);
    try {
      setCreated(await createToken({ name: name.trim(), scope, user_id: userId }));
      onCreated();
    } catch (err) {
      setError(err instanceof ApiError ? err.detail : NETWORK_MESSAGE);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="w-[min(480px,calc(100vw-32px))] rounded-[24px] border border-line-strong bg-raised p-6 text-ink backdrop:bg-black/60">
        {created ? (
          <>
            <DialogHeader>
              <DialogTitle className="text-lg font-semibold text-ink">Copy the token now</DialogTitle>
              <DialogDescription className="text-sm text-ink-dim">You won&apos;t see this token again.</DialogDescription>
            </DialogHeader>
            <div className="mt-5 grid gap-3">
              <code className="block break-all rounded-2xl border border-line bg-sunken px-4 py-3 font-mono text-[13px] text-ink">{created.token}</code>
              <div className="flex items-center justify-between gap-3">
                <p className="text-xs text-ink-muted">{created.note}</p>
                <CopyButton text={created.token} label="Copy token" />
              </div>
            </div>
            <div className="mt-6 flex justify-end">
              <Button size="sm" variant="primary" onClick={() => onOpenChange(false)}>Done</Button>
            </div>
          </>
        ) : (
          <>
            <DialogHeader>
              <DialogTitle className="text-lg font-semibold text-ink">Create an API token</DialogTitle>
              <DialogDescription className="text-sm text-ink-dim">A token acts as the user it belongs to, limited to its scope.</DialogDescription>
            </DialogHeader>
            <form className="mt-5 grid gap-4" onSubmit={submit} noValidate>
              <TextField data-bwignore="true" data-1p-ignore="true" data-lpignore="true" label="Name" value={name} onChange={(e) => setName(e.target.value)} placeholder="SIEM connector" />
              <div className="grid gap-1.5">
                <label htmlFor="token-user" className="text-[13px] font-medium text-ink-dim">User</label>
                <select id="token-user" value={userId} onChange={(e) => setUserId(Number(e.target.value))} className="h-11 rounded-[14px] border border-line-strong bg-raised px-3 text-sm text-ink focus:border-accent/60 focus:outline-none">
                  {users.map((u) => (
                    <option key={u.id} value={u.id}>{u.username}</option>
                  ))}
                </select>
              </div>
              <fieldset className="grid gap-2">
                <legend className="mb-1.5 text-[13px] font-medium text-ink-dim">Scope</legend>
                {SCOPES.map((s) => (
                  <label key={s.id} className={cn('flex cursor-pointer items-start gap-3 rounded-2xl border px-4 py-3 text-sm', scope === s.id ? 'border-accent/50 bg-accent/5' : 'border-line')}>
                    <input type="radio" name="scope" checked={scope === s.id} onChange={() => setScope(s.id)} className="mt-0.5 accent-[var(--accent)]" />
                    <span>
                      <span className="block font-medium text-ink">{s.label}</span>
                      <span className="block text-xs text-ink-muted">{s.text}</span>
                    </span>
                  </label>
                ))}
              </fieldset>
              {error && <p className="text-sm text-v-malicious" role="alert">{error}</p>}
              <div className="mt-2 flex justify-end gap-2">
                <Button size="sm" variant="ghost" onClick={() => onOpenChange(false)} disabled={busy}>Cancel</Button>
                <Button size="sm" variant="primary" type="submit" disabled={busy || users.length === 0}>Create token</Button>
              </div>
            </form>
          </>
        )}
      </DialogContent>
    </Dialog>
  );
}

export default function TokensScreen() {
  const toast = useToast();
  const [tokens, setTokens] = useState<Token[] | null>(null);
  const [users, setUsers] = useState<User[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [attempt, setAttempt] = useState(0);
  const [creating, setCreating] = useState(false);
  const [revoke, setRevoke] = useState<Token | null>(null);
  const [busy, setBusy] = useState(false);
  const [revokeError, setRevokeError] = useState<string | null>(null);

  useEffect(() => {
    const controller = new AbortController();
    setError(null);
    Promise.all([listTokens(controller.signal), listUsers(controller.signal)])
      .then(([t, u]) => {
        setTokens(t);
        setUsers(u);
      })
      .catch((e) => !isAbort(e) && setError(e instanceof ApiError ? e.detail : NETWORK_MESSAGE));
    return () => controller.abort();
  }, [attempt]);

  const owner = (id: number) => users.find((u) => u.id === id)?.username ?? `user ${id}`;

  return (
    <div className="grid max-w-5xl grid-cols-1 gap-8">
      <PageHeader
        eyebrow="Tokens"
        title="API tokens"
        description="For scripts and integrations that call the PhishHawk API."
        actions={
          <Button variant="primary" onClick={() => setCreating(true)} disabled={!tokens}>
            <KeyRound className="h-4 w-4" strokeWidth={1.75} /> Create token
          </Button>
        }
      />
      {error ? (
        <ErrorState detail={error} onRetry={() => setAttempt((a) => a + 1)} />
      ) : !tokens ? (
        <SkeletonRows rows={3} />
      ) : tokens.length === 0 ? (
        <EmptyState title="No API tokens yet." />
      ) : (
        <Card className="divide-y divide-line overflow-hidden">
          {tokens.map((t) => (
            <div key={t.id} className="flex flex-wrap items-center justify-between gap-4 px-5 py-4">
              <div className="min-w-0">
                <p className="flex flex-wrap items-center gap-2 text-sm font-medium text-ink">
                  {t.name}
                  <span className="rounded-full border border-line px-2 py-0.5 text-[11px] font-normal text-ink-dim">{t.scope}</span>
                  {t.revoked && <span className="rounded-full border border-v-malicious/30 px-2 py-0.5 text-[11px] text-v-malicious">Revoked</span>}
                </p>
                <p className="mt-0.5 text-xs text-ink-muted">
                  {owner(t.user_id)} · created <Time iso={t.created_at} relative />
                </p>
              </div>
              {!t.revoked && (
                <Button size="sm" variant="danger" onClick={() => setRevoke(t)}>Revoke</Button>
              )}
            </div>
          ))}
        </Card>
      )}

      <CreateTokenDialog open={creating} onOpenChange={setCreating} users={users.filter((u) => !u.disabled)} onCreated={() => listTokens().then(setTokens).catch(() => undefined)} />
      <ConfirmDialog
        open={revoke !== null}
        onOpenChange={(open) => {
          if (!open) {
            setRevoke(null);
            setRevokeError(null);
          }
        }}
        title={`Revoke ${revoke?.name ?? 'this token'}?`}
        body="Anything that uses this token stops working at once. This cannot be undone."
        confirmLabel="Revoke"
        danger
        busy={busy}
        error={revokeError}
        onConfirm={async () => {
          setBusy(true);
          setRevokeError(null);
          try {
            await revokeToken(revoke!.id);
            setTokens(await listTokens());
            toast('Token revoked.');
            setRevoke(null);
          } catch (e) {
            setRevokeError(e instanceof ApiError ? e.detail : NETWORK_MESSAGE);
          } finally {
            setBusy(false);
          }
        }}
      />
    </div>
  );
}
