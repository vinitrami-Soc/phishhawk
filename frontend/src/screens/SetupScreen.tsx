/* Setting the server up: the first account, made with the one-time code the
   server prints to its log (and `phishhawk server setup-code` prints again).
   That person owns the server and is the admin of their organization. Once
   anyone has an account, the page says so and leads to sign in. */

import { useEffect, useState, type FormEvent } from 'react';
import { LiquidMetalButton } from '@/components/threeui/liquid-metal/LiquidMetalButton';
import { AccountPage, CredentialFields, FormStatus, ProfileFields, accountFrom, useAccountForm } from '@/components/phishhawk/AccountForm';
import { getSetupState, setUp } from '@/api/client';
import { isAbort } from '@/api/errors';
import type { Session } from '@/api/types';
import { Link } from '@/app/router';
import { Skeleton, Switch, TextField } from '@/components/ui/ui';

export default function SetupScreen({ onEntered }: { onEntered: (session: Session) => void }) {
  const [open, setOpen] = useState<boolean | null>(null);
  const [signupOpen, setSignupOpen] = useState(false);
  const form = useAccountForm({ code: '', username: '', password: '', first_name: '', last_name: '', location: '', organization: '', job_title: '' });

  useEffect(() => {
    const controller = new AbortController();
    getSetupState(controller.signal)
      .then((state) => setOpen(state.open))
      .catch((error) => !isAbort(error) && setOpen(false));
    return () => controller.abort();
  }, []);

  function submit(event: FormEvent) {
    event.preventDefault();
    const v = form.values;
    void form.run(async () => {
      onEntered(await setUp({ ...accountFrom(v), code: v.code.trim(), organization: v.organization, signup_open: signupOpen }));
    });
  }

  if (open === null) {
    return (
      <AccountPage title="Set up PhishHawk">
        <Skeleton className="h-48 rounded-2xl" />
      </AccountPage>
    );
  }
  if (!open) {
    return (
      <AccountPage title="This server is set up" intro="Someone already has an account here, so there is nothing to set up.">
        <Link href="/app/login" className="text-sm font-medium text-accent underline-offset-4 hover:underline">
          Sign in
        </Link>
      </AccountPage>
    );
  }
  return (
    <AccountPage
      title="Set up PhishHawk"
      intro={
        <>
          No one has an account on this server yet. Enter the setup code from the server&apos;s log (or run{' '}
          <code className="rounded bg-sunken px-1.5 py-0.5 text-[13px]">phishhawk server setup-code</code>), then make your account. You will own this server.
        </>
      }
    >
      <form className="grid grid-cols-1 gap-4" onSubmit={submit} noValidate>
        <TextField label="Setup code" autoComplete="off" autoCapitalize="characters" spellCheck={false} placeholder="ABCD-EFGH-JKLM-NPQR" {...form.bind('code')} />
        <CredentialFields bind={form.bind} />
        <ProfileFields bind={form.bind} />
        <TextField label="Organization" autoComplete="organization" maxLength={80} hint="Your team's name. You can change it later." {...form.bind('organization')} />
        <div className="rounded-2xl border border-line bg-raised/60 px-4 py-3.5">
          <Switch
            checked={signupOpen}
            onChange={setSignupOpen}
            label="Let people create their own accounts"
            description="Anyone who can reach this server can then make an account of their own. You can change this later in Settings."
          />
        </div>
        <div className="mt-3 grid grid-cols-1 justify-items-center gap-3">
          <LiquidMetalButton type="submit" height={52} disabled={form.busy}>
            Set up
          </LiquidMetalButton>
          <FormStatus busy={form.busy} busyText="Setting up" general={form.general} />
        </div>
      </form>
    </AccountPage>
  );
}
