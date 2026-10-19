/* A link from a reset email (/app/reset/<token>): the account it is for, and
   its new password. The link works once, for an hour. The new password ends
   every session of the account, so the person then signs in with it. Someone
   signed in sees SignedInResetState (StateScreens) instead. */

import { useEffect, useState, type FormEvent } from 'react';
import { LiquidMetalButton } from '@/components/threeui/liquid-metal/LiquidMetalButton';
import { AccountPage, FormStatus, useAccountForm } from '@/components/phishhawk/AccountForm';
import { getResetLink, resetPassword } from '@/api/client';
import { ApiError, NETWORK_MESSAGE, isAbort } from '@/api/errors';
import { Link } from '@/app/router';
import { PasswordField, Skeleton } from '@/components/ui/ui';

type Loaded = { status: 'loading' } | { status: 'ready'; username: string } | { status: 'invalid'; detail: string };

const link = 'text-sm font-medium text-accent underline-offset-4 hover:underline';

export default function ResetScreen({ token }: { token: string }) {
  const [loaded, setLoaded] = useState<Loaded>({ status: 'loading' });
  const [done, setDone] = useState(false);
  const form = useAccountForm({ password: '' });

  useEffect(() => {
    const controller = new AbortController();
    getResetLink(token, controller.signal)
      .then(({ username }) => setLoaded({ status: 'ready', username }))
      .catch((error) => {
        if (isAbort(error)) return;
        const gone = error instanceof ApiError && error.status === 404;
        setLoaded({ status: 'invalid', detail: gone ? 'It was used already, is more than an hour old, or is not complete. Ask for a new one.' : NETWORK_MESSAGE });
      });
    return () => controller.abort();
  }, [token]);

  function submit(event: FormEvent) {
    event.preventDefault();
    if (!form.values.password) return;
    void form.run(async () => {
      await resetPassword(token, form.values.password);
      setDone(true);
    });
  }

  if (loaded.status === 'loading') {
    return (
      <AccountPage title="Choose a new password">
        <Skeleton className="h-32 rounded-2xl" />
      </AccountPage>
    );
  }
  if (loaded.status === 'invalid') {
    return (
      <AccountPage title="This link cannot be used" intro={loaded.detail}>
        <Link href="/app/forgot" className={link}>
          Ask for a new link
        </Link>
      </AccountPage>
    );
  }
  if (done) {
    return (
      <AccountPage title="Your password is changed" intro={`Every device signed in as ${loaded.username} was signed out. Sign in with the new password.`}>
        <Link href="/app/login" className={link}>
          Sign in
        </Link>
      </AccountPage>
    );
  }
  return (
    <AccountPage title="Choose a new password" intro={`For the account ${loaded.username}. Every device signed in to it is then signed out.`}>
      <form className="grid grid-cols-1 gap-4" onSubmit={submit} noValidate>
        {/* for a password manager: the account the new password belongs to */}
        <input type="text" name="username" autoComplete="username" value={loaded.username} readOnly hidden />
        <PasswordField label="New password" autoComplete="new-password" hint="At least 12 characters." {...form.bind('password')} />
        <div className="mt-3 grid grid-cols-1 justify-items-center gap-3">
          <LiquidMetalButton type="submit" height={52} disabled={form.busy || !form.values.password}>
            Set the new password
          </LiquidMetalButton>
          <FormStatus busy={form.busy} busyText="Saving" general={form.general} />
        </div>
      </form>
    </AccountPage>
  );
}
