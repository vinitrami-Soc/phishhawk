/* Joining an organization with an invitation link (/app/join/<token>). The
   page names the organization and the role the invitation gives; the person
   makes their own account and is signed in. An invitation works once, for 7
   days, and an admin can withdraw it. Someone already signed in sees
   SignedInInvitationState (StateScreens) instead: the link is for a new account. */

import { useEffect, useState, type FormEvent } from 'react';
import { LiquidMetalButton } from '@/components/threeui/liquid-metal/LiquidMetalButton';
import { AccountPage, CredentialFields, EmailField, FormStatus, ProfileFields, accountFrom, useAccountForm } from '@/components/phishhawk/AccountForm';
import { getInvitation, joinInvitation } from '@/api/client';
import { ApiError, NETWORK_MESSAGE, isAbort } from '@/api/errors';
import type { Invitation, Session } from '@/api/types';
import { Link } from '@/app/router';
import { ROLE_LABEL } from '@/app/vocabulary';
import { Skeleton } from '@/components/ui/ui';
import { useSendsMail } from '@/hooks/useGettingIn';

type Loaded = { status: 'loading' } | { status: 'ready'; invitation: Invitation } | { status: 'invalid'; detail: string };

export default function JoinScreen({ token, onEntered }: { token: string; onEntered: (session: Session) => void }) {
  const [loaded, setLoaded] = useState<Loaded>({ status: 'loading' });
  const form = useAccountForm({ username: '', password: '', email: '', first_name: '', last_name: '', location: '', job_title: '' });
  const sendsMail = useSendsMail();

  useEffect(() => {
    const controller = new AbortController();
    getInvitation(token, controller.signal)
      .then((invitation) => setLoaded({ status: 'ready', invitation }))
      .catch((error) => {
        if (isAbort(error)) return;
        const gone = error instanceof ApiError && error.status === 404;
        setLoaded({ status: 'invalid', detail: gone ? 'It was used already, withdrawn, or is more than 7 days old. Ask the admin who sent it for a new one.' : NETWORK_MESSAGE });
      });
    return () => controller.abort();
  }, [token]);

  function submit(event: FormEvent) {
    event.preventDefault();
    void form.run(async () => {
      onEntered(await joinInvitation(token, accountFrom(form.values)));
    });
  }

  if (loaded.status === 'loading') {
    return (
      <AccountPage title="Join an organization">
        <Skeleton className="h-48 rounded-2xl" />
      </AccountPage>
    );
  }
  if (loaded.status === 'invalid') {
    return (
      <AccountPage title="This invitation cannot be used" intro={loaded.detail}>
        <Link href="/app/login" className="text-sm font-medium text-accent underline-offset-4 hover:underline">
          Sign in
        </Link>
      </AccountPage>
    );
  }
  const { organization, role } = loaded.invitation;
  return (
    <AccountPage
      title={`Join ${organization}`}
      intro={`You are invited as an ${(ROLE_LABEL[role] ?? role).toLowerCase()}. Make your account to accept: you will see ${organization}'s analyses, and it will see your profile.`}
      footer={
        <>
          Have an account?{' '}
          <Link href="/app/login" className="font-medium text-ink-dim underline underline-offset-2 hover:text-ink">
            Sign in
          </Link>
        </>
      }
    >
      <form className="grid grid-cols-1 gap-4" onSubmit={submit} noValidate>
        <CredentialFields bind={form.bind} />
        <EmailField bind={form.bind} required={sendsMail} />
        <ProfileFields bind={form.bind} />
        <div className="mt-3 grid grid-cols-1 justify-items-center gap-3">
          <LiquidMetalButton type="submit" height={52} disabled={form.busy}>
            {organization.length > 24 ? 'Join the organization' : `Join ${organization}`}
          </LiquidMetalButton>
          <FormStatus busy={form.busy} busyText="Joining" general={form.general} />
        </div>
      </form>
    </AccountPage>
  );
}
