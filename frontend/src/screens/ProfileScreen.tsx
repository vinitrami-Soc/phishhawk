/* Your profile: first and last name, location and job title, seen only inside
   your workspace. An organization's admin also renames it here. A new password
   needs the current one and signs you out everywhere else; so does a new email
   address, since whoever has it can reset the password, and a link sent to it
   confirms it. The server checks everything before it changes anything. Someone
   on their own deletes their account here; in an organization its admins delete
   accounts. */

import { useEffect, useState, type FormEvent } from 'react';
import { CircleCheck } from 'lucide-react';
import { deleteMyAccount, getMe, patchMe } from '@/api/client';
import { ApiError, NETWORK_MESSAGE, isAbort } from '@/api/errors';
import type { Me, ProfilePatch, Session } from '@/api/types';
import { ROLE_LABEL } from '@/app/vocabulary';
import { FormStatus, PROFILE_KEYS, ProfileFields, sentence, useAccountForm } from '@/components/phishhawk/AccountForm';
import { Button, Card, ConfirmDialog, ErrorState, PageHeader, PasswordField, SectionTitle, Skeleton, TextField } from '@/components/ui/ui';
import { useToast } from '@/components/ui/toast';
import { useSendsMail } from '@/hooks/useGettingIn';

function Details({ me, onSaved }: { me: Me; onSaved: (me: Me) => void }) {
  const toast = useToast();
  const canRename = me.role === 'admin' && me.workspace.kind === 'organization';
  const form = useAccountForm({ ...me.profile, organization: me.workspace.name });

  function submit(event: FormEvent) {
    event.preventDefault();
    const patch: ProfilePatch = {};
    for (const key of PROFILE_KEYS) if (form.values[key] !== me.profile[key]) patch[key] = form.values[key];
    if (canRename && form.values.organization !== me.workspace.name) patch.organization = form.values.organization;
    if (!Object.keys(patch).length) return toast('Nothing to save.');
    void form.run(async () => {
      onSaved(await patchMe(patch));
      toast('Profile saved.');
    });
  }

  return (
    <Card className="p-5 sm:p-6">
      <SectionTitle>Profile</SectionTitle>
      <p className="mt-1 text-[13px] text-ink-muted">
        Seen only inside {me.workspace.kind === 'individual' ? 'your workspace' : me.workspace.name}.
      </p>
      <form className="mt-5 grid grid-cols-1 gap-4" onSubmit={submit} noValidate>
        <ProfileFields bind={form.bind} />
        {canRename && <TextField label="Organization name" autoComplete="organization" maxLength={80} hint="Everyone in it sees the new name." {...form.bind('organization')} />}
        <div className="flex flex-wrap items-center justify-end gap-3">
          <FormStatus busy={form.busy} busyText="Saving" general={form.general} />
          <Button variant="primary" type="submit" disabled={form.busy}>
            Save profile
          </Button>
        </div>
      </form>
    </Card>
  );
}

function Email({ me, onSaved }: { me: Me; onSaved: (me: Me) => void }) {
  const toast = useToast();
  const sendsMail = useSendsMail();
  const saved = me.email ?? '';
  const form = useAccountForm({ email: saved, current_password: '' });
  const unchanged = form.values.email.trim().toLowerCase() === saved;
  const again = unchanged && Boolean(saved) && !me.email_verified && sendsMail; // the same address: its link again
  const ready = Boolean(form.values.current_password) && (!unchanged || again);

  function submit(event: FormEvent) {
    event.preventDefault();
    if (!ready) return;
    void form.run(async () => {
      const next = await patchMe({ email: form.values.email.trim(), current_password: form.values.current_password });
      form.setValues({ email: next.email ?? '', current_password: '' });
      onSaved(next);
      toast(!next.email ? 'Email address removed.' : sendsMail ? `A link is on its way to ${next.email}. Open it to confirm the address.` : 'Email address saved.');
    });
  }

  const status = !saved
    ? sendsMail
      ? 'None yet. Without one, a forgotten password needs an admin.'
      : 'None yet. This server sends no email for now.'
    : me.email_verified
      ? null
      : sendsMail
        ? `${saved} is not confirmed yet: open the link sent to it. Until then no reset link goes to it.`
        : `${saved} is kept for when this server sends email.`;
  return (
    <Card className="p-5 sm:p-6">
      <SectionTitle>Email</SectionTitle>
      {status ? (
        <p className="mt-1 text-[13px] text-ink-muted">{status}</p>
      ) : (
        <p className="mt-1 flex items-center gap-1.5 text-[13px] text-ink-muted">
          <CircleCheck className="h-3.5 w-3.5 shrink-0 text-accent" strokeWidth={1.75} aria-hidden="true" />
          <span className="min-w-0 break-all">{saved} is confirmed: a forgotten password can be reset with it.</span>
        </p>
      )}
      <form className="mt-5 grid grid-cols-1 gap-4" onSubmit={submit} noValidate>
        <TextField label="Email address" type="email" inputMode="email" autoComplete="email" autoCapitalize="none" spellCheck={false} maxLength={254} hint="Leave it empty for none." {...form.bind('email')} />
        <PasswordField label="Current password" autoComplete="current-password" hint="Whoever has the address can reset your password, so changing it needs your password." {...form.bind('current_password')} />
        <div className="flex flex-wrap items-center justify-end gap-3">
          <FormStatus busy={form.busy} busyText="Saving" general={form.general} />
          <Button type="submit" disabled={form.busy || !ready}>
            {again ? 'Send the link again' : 'Save email'}
          </Button>
        </div>
      </form>
    </Card>
  );
}

function Password() {
  const toast = useToast();
  const form = useAccountForm({ current_password: '', password: '' });

  function submit(event: FormEvent) {
    event.preventDefault();
    if (!form.values.current_password || !form.values.password) return;
    void form.run(async () => {
      await patchMe({ current_password: form.values.current_password, password: form.values.password });
      form.setValues({ current_password: '', password: '' });
      toast('Password changed. You were signed out everywhere else.');
    });
  }

  return (
    <Card className="p-5 sm:p-6">
      <SectionTitle>Password</SectionTitle>
      <p className="mt-1 text-[13px] text-ink-muted">A new password signs you out on every other device.</p>
      <form className="mt-5 grid grid-cols-1 gap-4" onSubmit={submit} noValidate>
        <PasswordField label="Current password" autoComplete="current-password" {...form.bind('current_password')} />
        <PasswordField label="New password" autoComplete="new-password" hint="At least 12 characters." {...form.bind('password')} />
        <div className="flex flex-wrap items-center justify-end gap-3">
          <FormStatus busy={form.busy} busyText="Changing" general={form.general} />
          <Button type="submit" disabled={form.busy || !form.values.current_password || !form.values.password}>
            Change password
          </Button>
        </div>
      </form>
    </Card>
  );
}

function DeleteAccount({ me, onDeleted }: { me: Me; onDeleted: () => void }) {
  const toast = useToast();
  const [password, setPassword] = useState('');
  const [confirming, setConfirming] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function remove() {
    setBusy(true);
    setError(null);
    try {
      await deleteMyAccount(password);
      toast('Your account was deleted.');
      onDeleted();
    } catch (e) {
      setError(e instanceof ApiError ? sentence(e.detail) : NETWORK_MESSAGE);
    } finally {
      setBusy(false);
    }
  }

  return (
    <section aria-labelledby="delete-account-title">
      <Card className="p-5 sm:p-6">
        <div id="delete-account-title">
          <SectionTitle>Delete your account</SectionTitle>
        </div>
        <p className="mt-1 text-[13px] text-ink-muted">Your account and your workspace go for good, with every message, report, batch, campaign, mailbox and setting in it.</p>
        <form
          className="mt-5 grid grid-cols-1 gap-4"
          onSubmit={(event) => {
            event.preventDefault();
            if (password) setConfirming(true);
          }}
          noValidate
        >
          <PasswordField label="Password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} hint="Your password, to show it is you." />
          <div className="flex justify-end">
            <Button variant="danger" type="submit" disabled={!password}>
              Delete my account
            </Button>
          </div>
        </form>
      </Card>
      <ConfirmDialog
        open={confirming}
        onOpenChange={(open) => {
          if (!open) {
            setConfirming(false);
            setError(null);
          }
        }}
        title="Delete your account?"
        body={`Everything in ${me.workspace.name} goes, for good, and you are signed out. This cannot be undone.`}
        confirmLabel="Delete my account"
        danger
        busy={busy}
        error={error}
        onConfirm={remove}
      />
    </section>
  );
}

export default function ProfileScreen({ session, onChanged, onDeleted }: { session: Session; onChanged: () => void; onDeleted: () => void }) {
  const [me, setMe] = useState<Me | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    const controller = new AbortController();
    setError(null);
    getMe(controller.signal)
      .then(setMe)
      .catch((e) => !isAbort(e) && setError(e instanceof ApiError ? e.detail : NETWORK_MESSAGE));
    return () => controller.abort();
  }, [attempt]);

  const role = ROLE_LABEL[session.role] ?? session.role;
  return (
    <div className="grid max-w-3xl grid-cols-1 gap-6">
      <PageHeader
        eyebrow="Profile"
        title="Your profile"
        description={me ? `${me.username}, ${role.toLowerCase()} of ${me.workspace.name}${me.owner ? '. You own this server.' : '.'}` : undefined}
      />
      {error && <ErrorState detail={error} onRetry={() => setAttempt((a) => a + 1)} />}
      {!me && !error && <Skeleton className="h-96 rounded-[20px]" />}
      {me && (
        <>
          <Details
            me={me}
            onSaved={(saved) => {
              setMe(saved);
              onChanged();
            }}
          />
          <Email
            me={me}
            onSaved={(saved) => {
              setMe(saved);
              onChanged();
            }}
          />
          <Password />
          {me.workspace.kind === 'individual' && !me.owner && <DeleteAccount me={me} onDeleted={onDeleted} />}
          {me.workspace.kind === 'organization' && !me.owner && <p className="text-[13px] text-ink-muted">To delete your account, ask an admin of {me.workspace.name}.</p>}
        </>
      )}
    </div>
  );
}
