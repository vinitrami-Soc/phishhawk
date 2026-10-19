/* A link from a confirmation email (/app/verify-email/<token>): one press
   confirms the address, and reset links can then go to it. On a press, not on
   opening: a mail scanner that opens every link confirms nothing. Signed out,
   the page stands alone; signed in, it opens in the console, and the session
   is read again so the profile shows the address as confirmed. */

import { useState, type ReactNode } from 'react';
import { LiquidMetalButton } from '@/components/threeui/liquid-metal/LiquidMetalButton';
import { AccountPage, FormStatus, sentence } from '@/components/phishhawk/AccountForm';
import { verifyEmail } from '@/api/client';
import { ApiError, NETWORK_MESSAGE } from '@/api/errors';
import { Link } from '@/app/router';
import { Card, PageHeader } from '@/components/ui/ui';

type State = 'ready' | 'busy' | 'done' | 'invalid';

const TEXT: Record<Exclude<State, 'busy'>, { title: string; intro: string }> = {
  ready: { title: 'Confirm your email address', intro: 'Confirm that this address is yours: links to reset your password can then go to it.' },
  done: { title: 'Your email address is confirmed', intro: 'If you forget your password, a link to choose a new one can now go to it.' },
  invalid: { title: 'This link cannot be used', intro: 'It was used already, is more than 24 hours old, or the address on the account changed since. Save the address on your profile again for a new link.' },
};

function Frame({ signedIn, title, intro, children }: { signedIn: boolean; title: string; intro: string; children: ReactNode }) {
  if (!signedIn) {
    return (
      <AccountPage title={title} intro={intro}>
        {children}
      </AccountPage>
    );
  }
  return (
    <div className="grid max-w-2xl grid-cols-1 gap-6">
      <PageHeader eyebrow="Email" title={title} description={intro} />
      <Card className="p-5 sm:p-6">{children}</Card>
    </div>
  );
}

export default function VerifyEmailScreen({ token, signedIn, onConfirmed }: { token: string; signedIn: boolean; onConfirmed?: () => void }) {
  const [state, setState] = useState<State>('ready');
  const [error, setError] = useState<string | null>(null);

  async function confirm() {
    setState('busy');
    setError(null);
    try {
      await verifyEmail(token);
      setState('done');
      onConfirmed?.();
    } catch (e) {
      if (e instanceof ApiError && e.status === 404) return setState('invalid');
      setState('ready');
      setError(e instanceof ApiError ? sentence(e.detail) : NETWORK_MESSAGE);
    }
  }

  const { title, intro } = TEXT[state === 'busy' ? 'ready' : state];
  const next = signedIn ? { href: '/app/profile', label: 'Your profile' } : { href: '/app/login', label: 'Sign in' };
  return (
    <Frame signedIn={signedIn} title={title} intro={intro}>
      {state === 'ready' || state === 'busy' ? (
        <div className="grid grid-cols-1 justify-items-center gap-3">
          <LiquidMetalButton height={52} disabled={state === 'busy'} onClick={() => void confirm()}>
            Confirm my address
          </LiquidMetalButton>
          <FormStatus busy={state === 'busy'} busyText="Confirming" general={error} />
        </div>
      ) : (
        <Link href={next.href} className="text-sm font-medium text-accent underline-offset-4 hover:underline">
          {next.label}
        </Link>
      )}
    </Frame>
  );
}
