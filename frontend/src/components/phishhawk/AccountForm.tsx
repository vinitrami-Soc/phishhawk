/* What the screens for getting in share: the page around the form (the sign-in
   page's card, alone, with room below for the theme toggle), the account and
   profile fields, and a form state that puts each refusal next to its field.
   The server names the field a refusal is about ("last_name: required");
   everything else is said under the button. */

import { useState, type ChangeEvent, type ReactNode } from 'react';
import { ArrowLeft } from 'lucide-react';
import { Spotlight } from '@/components/core/spotlight';
import { TextRoll } from '@/components/core/text-roll';
import { ApiError, NETWORK_MESSAGE, fieldOf } from '@/api/errors';
import type { AccountFields } from '@/api/types';
import { Link, asset } from '@/app/router';
import { Panel, PasswordField, TextField } from '@/components/ui/ui';

/** A sentence: the server's details are lower case and have no full stop. */
export function sentence(text: string): string {
  const trimmed = text.trim();
  if (!trimmed) return trimmed;
  return `${trimmed[0].toUpperCase()}${trimmed.slice(1)}${/[.!?]$/.test(trimmed) ? '' : '.'}`;
}

export function AccountPage({ title, intro, children, footer }: { title: string; intro?: ReactNode; children: ReactNode; footer?: ReactNode }) {
  return (
    <main id="main" tabIndex={-1} className="relative mx-auto grid min-h-dvh w-full max-w-[600px] grid-cols-1 content-center gap-4 px-4 pt-10 pb-24 focus:outline-none">
      <Link href="/app/" className="inline-flex w-max items-center gap-1.5 rounded-full px-2 py-1 text-[13px] text-ink-muted transition-colors hover:text-ink">
        <ArrowLeft className="h-3.5 w-3.5" strokeWidth={1.75} aria-hidden="true" />
        About PhishHawk
      </Link>
      <Panel>
        <div className="relative overflow-hidden rounded-[22px] px-6 py-8 sm:px-9 sm:py-10">
          <Spotlight className="bg-accent/15 blur-3xl" size={240} />
          <Link href="/app/" aria-label="PhishHawk home" className="relative flex w-max items-center gap-3 rounded-2xl">
            <img src={asset('brand/phishhawk-mark.svg')} alt="" className="h-11 w-11" />
            <TextRoll className="text-xl font-semibold tracking-[-0.018em] text-ink">PhishHawk</TextRoll>
          </Link>
          <h1 className="relative mt-6 text-[26px] font-semibold leading-tight tracking-[-0.02em] text-ink">{title}</h1>
          {intro && <div className="relative mt-2 text-[15px] text-ink-dim">{intro}</div>}
          <div className="relative mt-7">{children}</div>
        </div>
      </Panel>
      {footer && <div className="text-center text-[13px] text-ink-muted">{footer}</div>}
      <p className="text-center text-xs text-ink-muted">
        An account sets one cookie, only to keep you signed in.{' '}
        <Link href="/app/privacy" className="text-ink-dim underline underline-offset-2 hover:text-ink">
          Privacy and terms
        </Link>
      </p>
    </main>
  );
}

export type Bind = (name: string) => { value: string; onChange: (event: ChangeEvent<HTMLInputElement>) => void; error: string | null };

/** The values of a form, the refusal for each field, and one message for the rest. */
export function useAccountForm(initial: Record<string, string>) {
  const [values, setValues] = useState(initial);
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [general, setGeneral] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const bind: Bind = (name) => ({
    value: values[name] ?? '',
    onChange: (event) => {
      const next = event.target.value;
      setValues((v) => ({ ...v, [name]: next }));
      setErrors(({ [name]: _gone, ...rest }) => rest);
    },
    error: errors[name] ?? null,
  });

  /** Runs what the form does; a refusal goes next to its field when it names one this form has. */
  async function run(action: () => Promise<void>) {
    if (busy) return;
    setBusy(true);
    setGeneral(null);
    setErrors({});
    try {
      await action();
    } catch (error) {
      if (!(error instanceof ApiError)) setGeneral(NETWORK_MESSAGE);
      else if (error.status === 429) setGeneral(`Too many tries. Try again in ${error.retryAfter ?? 60} seconds.`);
      else {
        const { field, message } = fieldOf(error.detail);
        if (field && field in values) setErrors({ [field]: message });
        else setGeneral(sentence(error.detail));
      }
    } finally {
      setBusy(false);
    }
  }

  return { values, setValues, bind, errors, general, busy, run };
}

/** Username and password of a new account. */
export function CredentialFields({ bind }: { bind: Bind }) {
  return (
    <>
      <TextField
        label="Username"
        autoComplete="username"
        autoCapitalize="none"
        spellCheck={false}
        maxLength={64}
        hint="3 to 64 lowercase letters, digits, dots, dashes or underscores. You sign in with it."
        {...bind('username')}
      />
      <PasswordField label="Password" autoComplete="new-password" hint="At least 12 characters." {...bind('password')} />
    </>
  );
}

/** First and last name, location and job title: seen only inside the workspace. */
export function ProfileFields({ bind }: { bind: Bind }) {
  return (
    <>
      <div className="grid grid-cols-1 items-start gap-4 sm:grid-cols-2">
        <TextField label="First name" autoComplete="given-name" maxLength={80} {...bind('first_name')} />
        <TextField label="Last name" autoComplete="family-name" maxLength={80} {...bind('last_name')} />
      </div>
      <TextField label="Location" autoComplete="address-level2" maxLength={80} hint="A city or a country." {...bind('location')} />
      <TextField label="Job title (optional)" autoComplete="organization-title" maxLength={80} {...bind('job_title')} />
    </>
  );
}

/** The message under the button: what is happening, or what went wrong that no field explains. */
export function FormStatus({ busy, busyText, general }: { busy: boolean; busyText: string; general: string | null }) {
  return (
    <div className="min-h-5 text-center text-sm" aria-live="polite">
      {busy && <span className="text-ink-muted">{busyText}</span>}
      {!busy && general && (
        <span className="text-v-malicious" role="alert">
          {general}
        </span>
      )}
    </div>
  );
}

export const PROFILE_KEYS = ['first_name', 'last_name', 'location', 'job_title'] as const;

/** A new account's fields from a form: the username as the server keeps it (lower case, no spaces around). */
export function accountFrom(values: Record<string, string>): AccountFields {
  return {
    username: (values.username ?? '').trim().toLowerCase(),
    password: values.password ?? '',
    first_name: values.first_name ?? '',
    last_name: values.last_name ?? '',
    location: values.location ?? '',
    job_title: values.job_title ?? '',
  };
}
