/* Users (admin): who can sign in, and with which role. This is where accounts
   are created; there is no self sign-up. */

import { useEffect, useState, type FormEvent } from 'react';
import { UserPlus } from 'lucide-react';
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from '@/components/core/dialog';
import { createUser, listUsers, updateUser } from '@/api/client';
import { ApiError, NETWORK_MESSAGE, isAbort } from '@/api/errors';
import type { Role, Session, User } from '@/api/types';
import { ROLE_LABEL } from '@/app/vocabulary';
import { Button, Card, ConfirmDialog, ErrorState, PageHeader, PasswordField, SkeletonRows, TextField, Time } from '@/components/ui/ui';
import { useToast } from '@/components/ui/toast';
import { cn } from '@/lib/utils';

type Change = { user: User; kind: 'role' | 'disable' | 'enable' } | null;

function AddUserDialog({ open, onOpenChange, onCreated }: { open: boolean; onOpenChange: (o: boolean) => void; onCreated: (u: User) => void }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [role, setRole] = useState<Role>('analyst');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (open) {
      setUsername('');
      setPassword('');
      setRole('analyst');
      setError(null);
    }
  }, [open]);

  async function submit(e: FormEvent) {
    e.preventDefault();
    const name = username.trim().toLowerCase();
    if (!/^[a-z0-9][a-z0-9._-]{2,63}$/.test(name)) return setError('Use 3 to 64 characters: lowercase letters, digits, dot, hyphen or underscore.');
    if (password.length < 12) return setError('The password needs at least 12 characters.');
    setBusy(true);
    setError(null);
    try {
      onCreated(await createUser({ username: name, password, role }));
      onOpenChange(false);
    } catch (err) {
      setError(err instanceof ApiError ? err.detail : NETWORK_MESSAGE);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="w-[min(460px,calc(100vw-32px))] rounded-[24px] border border-line-strong bg-raised p-6 text-ink backdrop:bg-black/60">
        <DialogHeader>
          <DialogTitle className="text-lg font-semibold text-ink">Add a user</DialogTitle>
          <DialogDescription className="text-sm text-ink-dim">They sign in with this username and password. Share the password safely.</DialogDescription>
        </DialogHeader>
        <form className="mt-5 grid gap-4" onSubmit={submit} noValidate>
          <TextField data-bwignore="true" data-1p-ignore="true" data-lpignore="true" label="Username" value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="off" hint="Lowercase letters, digits, dot, hyphen or underscore." />
          <PasswordField data-bwignore="true" data-1p-ignore="true" data-lpignore="true" label="Password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="new-password" hint="At least 12 characters." />
          <fieldset className="grid gap-2">
            <legend className="mb-1.5 text-[13px] font-medium text-ink-dim">Role</legend>
            {(['analyst', 'admin'] as const).map((r) => (
              <label key={r} className={cn('flex cursor-pointer items-start gap-3 rounded-2xl border px-4 py-3 text-sm', role === r ? 'border-accent/50 bg-accent/5' : 'border-line')}>
                <input type="radio" name="role" checked={role === r} onChange={() => setRole(r)} className="mt-0.5 accent-[var(--accent)]" />
                <span>
                  <span className="block font-medium text-ink">{ROLE_LABEL[r]}</span>
                  <span className="block text-xs text-ink-muted">{r === 'admin' ? 'Everything, including settings, users and tokens.' : 'Analyses, the queue and their own audit entries.'}</span>
                </span>
              </label>
            ))}
          </fieldset>
          {error && <p className="text-sm text-v-malicious" role="alert">{error}</p>}
          <div className="mt-2 flex justify-end gap-2">
            <Button size="sm" variant="ghost" onClick={() => onOpenChange(false)} disabled={busy}>Cancel</Button>
            <Button size="sm" variant="primary" type="submit" disabled={busy}>Add user</Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}

export default function UsersScreen({ session }: { session: Session }) {
  const toast = useToast();
  const [users, setUsers] = useState<User[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [attempt, setAttempt] = useState(0);
  const [adding, setAdding] = useState(false);
  const [change, setChange] = useState<Change>(null);
  const [busy, setBusy] = useState(false);
  const [changeError, setChangeError] = useState<string | null>(null);

  useEffect(() => {
    const controller = new AbortController();
    setError(null);
    listUsers(controller.signal)
      .then(setUsers)
      .catch((e) => !isAbort(e) && setError(e instanceof ApiError ? e.detail : NETWORK_MESSAGE));
    return () => controller.abort();
  }, [attempt]);

  async function apply() {
    if (!change) return;
    setBusy(true);
    setChangeError(null);
    try {
      const patch = change.kind === 'role' ? { role: (change.user.role === 'admin' ? 'analyst' : 'admin') as Role } : { disabled: change.kind === 'disable' };
      const updated = await updateUser(change.user.id, patch);
      setUsers((list) => list?.map((u) => (u.id === updated.id ? updated : u)) ?? null);
      toast('User updated.');
      setChange(null);
    } catch (e) {
      setChangeError(e instanceof ApiError ? e.detail : NETWORK_MESSAGE);
    } finally {
      setBusy(false);
    }
  }

  const confirmText = change && {
    role: { title: `Make ${change.user.username} ${change.user.role === 'admin' ? 'an analyst' : 'an admin'}?`, body: change.user.role === 'admin' ? 'They lose access to settings, users and tokens.' : 'They get access to settings, users and tokens.', label: 'Change role' },
    disable: { title: `Disable ${change.user.username}?`, body: 'They can no longer sign in. Their analyses and audit entries stay.', label: 'Disable' },
    enable: { title: `Enable ${change.user.username}?`, body: 'They can sign in again.', label: 'Enable' },
  }[change.kind];

  return (
    <div className="grid max-w-5xl grid-cols-1 gap-8">
      <PageHeader
        eyebrow="Users"
        title="Users"
        description="Who can sign in to PhishHawk, and what they can do."
        actions={
          <Button variant="primary" onClick={() => setAdding(true)}>
            <UserPlus className="h-4 w-4" strokeWidth={1.75} /> Add user
          </Button>
        }
      />
      {error ? (
        <ErrorState detail={error} onRetry={() => setAttempt((a) => a + 1)} />
      ) : !users ? (
        <SkeletonRows rows={3} />
      ) : (
        <Card className="divide-y divide-line overflow-hidden">
          {users.map((u) => {
            const self = u.id === session.user_id;
            return (
              <div key={u.id} className="flex flex-wrap items-center justify-between gap-4 px-5 py-4">
                <div className="min-w-0">
                  <p className="flex flex-wrap items-center gap-2 text-sm font-medium text-ink">
                    {u.username}
                    {self && <span className="text-xs font-normal text-ink-muted">(you)</span>}
                    <span className={cn('rounded-full border px-2 py-0.5 text-[11px] font-medium', u.role === 'admin' ? 'border-accent/40 text-accent' : 'border-line text-ink-dim')}>{ROLE_LABEL[u.role]}</span>
                    {u.disabled && <span className="rounded-full border border-v-malicious/30 px-2 py-0.5 text-[11px] text-v-malicious">Disabled</span>}
                  </p>
                  <p className="mt-0.5 text-xs text-ink-muted">Last sign-in: {u.last_login_at ? <Time iso={u.last_login_at} relative /> : 'never'}</p>
                </div>
                {!self && (
                  <div className="flex gap-2">
                    <Button size="sm" variant="ghost" onClick={() => setChange({ user: u, kind: 'role' })}>
                      Make {u.role === 'admin' ? 'analyst' : 'admin'}
                    </Button>
                    <Button size="sm" variant={u.disabled ? 'secondary' : 'danger'} onClick={() => setChange({ user: u, kind: u.disabled ? 'enable' : 'disable' })}>
                      {u.disabled ? 'Enable' : 'Disable'}
                    </Button>
                  </div>
                )}
              </div>
            );
          })}
        </Card>
      )}

      <AddUserDialog
        open={adding}
        onOpenChange={setAdding}
        onCreated={(u) => {
          setUsers((list) => [...(list ?? []), u]);
          toast(`${u.username} can now sign in.`);
        }}
      />
      <ConfirmDialog
        open={change !== null}
        onOpenChange={(open) => {
          if (!open) {
            setChange(null);
            setChangeError(null);
          }
        }}
        title={confirmText?.title ?? ''}
        body={confirmText?.body ?? ''}
        confirmLabel={confirmText?.label ?? 'Confirm'}
        danger={change?.kind === 'disable'}
        busy={busy}
        error={changeError}
        onConfirm={apply}
      />
    </div>
  );
}
