/* A forgotten password (/app/forgot): a username or an email address, and a
   link by email to choose a new password. The server answers the same whether
   or not an account matches, and the page shows that answer as it is. The link
   goes only to an address whose own confirmation link was opened, and lasts an
   hour. A server that sends no mail resets no password: an admin sets a new one. */

import { useEffect, useState, type FormEvent } from 'react';
import { LiquidMetalButton } from '@/components/threeui/liquid-metal/LiquidMetalButton';
import { AccountPage, FormStatus, sentence, useAccountForm } from '@/components/phishhawk/AccountForm';
import { getResetState, requestReset } from '@/api/client';
import { isAbort } from '@/api/errors';
import { Link } from '@/app/router';
import { Button, Skeleton, TextField } from '@/components/ui/ui';

const signIn = (
  <>
    Remembered it?{' '}
    <Link href="/app/login" className="font-medium text-ink-dim underline underline-offset-2 hover:text-ink">
      Sign in
    </Link>
  </>
);

export default function ForgotScreen() {
  const [available, setAvailable] = useState<boolean | null>(null);
  const [answer, setAnswer] = useState<string | null>(null);
  const form = useAccountForm({ login: '' });
  const login = form.values.login.trim();

  useEffect(() => {
    const controller = new AbortController();
    getResetState(controller.signal)
      .then((state) => setAvailable(state.available))
      .catch((error) => !isAbort(error) && setAvailable(false));
    return () => controller.abort();
  }, []);

  function submit(event: FormEvent) {
    event.preventDefault();
    if (!login) return;
    void form.run(async () => {
      setAnswer(sentence((await requestReset(login)).detail));
    });
  }

  if (available === null) {
    return (
      <AccountPage title="Forgot your password?">
        <Skeleton className="h-32 rounded-2xl" />
      </AccountPage>
    );
  }
  if (!available) {
    return (
      <AccountPage title="Ask an admin for a new password" intro="This server sends no email, so it cannot send you a link. An admin of your organization can set a new password for you." footer={signIn}>
        <Link href="/app/login" className="text-sm font-medium text-accent underline-offset-4 hover:underline">
          Sign in
        </Link>
      </AccountPage>
    );
  }
  if (answer) {
    return (
      <AccountPage title="Check your email" intro={answer} footer={signIn}>
        <div className="grid gap-4 text-sm text-ink-dim">
          <p>The link lasts an hour and works once. Nothing there after a few minutes? Look in the spam folder, and check that the address on your profile was confirmed.</p>
          <Button
            className="w-max"
            onClick={() => {
              setAnswer(null);
              form.setValues({ login: '' });
            }}
          >
            Ask again
          </Button>
        </div>
      </AccountPage>
    );
  }
  return (
    <AccountPage title="Forgot your password?" intro="Enter your username or your email address. A link to choose a new password goes to the account's confirmed email address." footer={signIn}>
      <form className="grid grid-cols-1 gap-4" onSubmit={submit} noValidate>
        <TextField label="Username or email" autoComplete="username" autoCapitalize="none" spellCheck={false} maxLength={254} {...form.bind('login')} />
        <div className="mt-3 grid grid-cols-1 justify-items-center gap-3">
          <LiquidMetalButton type="submit" height={52} disabled={form.busy || !login}>
            Send the link
          </LiquidMetalButton>
          <FormStatus busy={form.busy} busyText="Sending" general={form.general} />
        </div>
      </form>
      {import.meta.env.DEV && <p className="mt-4 rounded-xl border border-dashed border-line-strong px-3 py-2 text-center text-xs text-ink-muted">Development preview: the link is in the browser&apos;s console.</p>}
    </AccountPage>
  );
}
