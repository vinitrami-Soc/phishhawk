/* Create an account, while the server's owner allows it. First who it is for:
   just me (a workspace for one person, nothing to approve) or my organization
   (a team, with this person as its admin, who then invites the others). Then
   the account and profile, with an email address when the server sends mail. A
   new account starts empty and sees nothing of anyone else's. */

import { useEffect, useState, type FormEvent } from 'react';
import { ArrowLeft, Building2, UserRound, type LucideIcon } from 'lucide-react';
import { LiquidMetalButton } from '@/components/threeui/liquid-metal/LiquidMetalButton';
import { AccountPage, CredentialFields, EmailField, FormStatus, ProfileFields, accountFrom, useAccountForm } from '@/components/phishhawk/AccountForm';
import { getSignupState, signUp } from '@/api/client';
import { isAbort } from '@/api/errors';
import type { Session, Workspace } from '@/api/types';
import { Link } from '@/app/router';
import { Skeleton, TextField } from '@/components/ui/ui';
import { useSendsMail } from '@/hooks/useGettingIn';

type Kind = Workspace['kind'];

const KINDS: { kind: Kind; icon: LucideIcon; title: string; text: string }[] = [
  { kind: 'individual', icon: UserRound, title: 'Just me', text: 'Check the mail you receive. No one else is involved and nothing needs approving.' },
  { kind: 'organization', icon: Building2, title: 'My organization', text: 'A workspace for your team. You are its admin and invite the others.' },
];

const signIn = (
  <>
    Have an account?{' '}
    <Link href="/app/login" className="font-medium text-ink-dim underline underline-offset-2 hover:text-ink">
      Sign in
    </Link>
  </>
);

export default function SignupScreen({ onEntered }: { onEntered: (session: Session) => void }) {
  const [open, setOpen] = useState<boolean | null>(null);
  const [kind, setKind] = useState<Kind | null>(null);
  const form = useAccountForm({ username: '', password: '', email: '', first_name: '', last_name: '', location: '', organization: '', job_title: '' });
  const sendsMail = useSendsMail();

  useEffect(() => {
    const controller = new AbortController();
    getSignupState(controller.signal)
      .then((state) => setOpen(state.open))
      .catch((error) => !isAbort(error) && setOpen(false));
    return () => controller.abort();
  }, []);

  function submit(event: FormEvent) {
    event.preventDefault();
    if (!kind) return;
    const v = form.values;
    void form.run(async () => {
      onEntered(await signUp({ ...accountFrom(v), kind, organization: v.organization }));
    });
  }

  if (open === null) {
    return (
      <AccountPage title="Create an account">
        <Skeleton className="h-48 rounded-2xl" />
      </AccountPage>
    );
  }
  if (!open) {
    return (
      <AccountPage title="Accounts are made by invitation" intro="This server does not take new accounts. Ask your PhishHawk admin for an invitation link." footer={signIn}>
        <Link href="/app/login" className="text-sm font-medium text-accent underline-offset-4 hover:underline">
          Sign in
        </Link>
      </AccountPage>
    );
  }
  if (!kind) {
    return (
      <AccountPage title="Create an account" intro="Who is it for?" footer={signIn}>
        <ul className="grid grid-cols-1 gap-3">
          {KINDS.map(({ kind: value, icon: Icon, title, text }) => (
            <li key={value}>
              <button
                type="button"
                onClick={() => setKind(value)}
                className="group flex w-full items-start gap-4 rounded-2xl border border-line bg-raised/60 p-4 text-left transition-colors duration-300 hover:border-accent/50 hover:bg-accent/5"
              >
                <span className="grid h-11 w-11 shrink-0 place-items-center rounded-xl border border-line bg-surface text-accent">
                  <Icon className="h-5 w-5" strokeWidth={1.5} aria-hidden="true" />
                </span>
                <span className="min-w-0">
                  <span className="block text-[15px] font-medium text-ink">{title}</span>
                  <span className="mt-0.5 block text-[13px] text-ink-muted">{text}</span>
                </span>
              </button>
            </li>
          ))}
        </ul>
      </AccountPage>
    );
  }
  const chosen = KINDS.find((k) => k.kind === kind)!;
  return (
    <AccountPage
      title={kind === 'organization' ? 'Create your organization' : 'Create your account'}
      intro={
        <button type="button" onClick={() => setKind(null)} className="inline-flex min-h-8 items-center gap-1.5 text-[13px] text-ink-muted transition-colors hover:text-ink">
          <ArrowLeft className="h-3.5 w-3.5" strokeWidth={1.75} aria-hidden="true" />
          {chosen.title}: change
        </button>
      }
      footer={signIn}
    >
      <form className="grid grid-cols-1 gap-4" onSubmit={submit} noValidate>
        <CredentialFields bind={form.bind} />
        <EmailField bind={form.bind} required={sendsMail} />
        <ProfileFields bind={form.bind} />
        <TextField
          label={kind === 'organization' ? 'Organization' : 'Organization (optional)'}
          autoComplete="organization"
          maxLength={80}
          hint={kind === 'organization' ? "Your team's name, as its members will see it." : 'Where you work, if you like.'}
          {...form.bind('organization')}
        />
        <div className="mt-3 grid grid-cols-1 justify-items-center gap-3">
          <LiquidMetalButton type="submit" height={52} disabled={form.busy}>
            Create account
          </LiquidMetalButton>
          <FormStatus busy={form.busy} busyText="Creating your account" general={form.general} />
        </div>
      </form>
    </AccountPage>
  );
}
