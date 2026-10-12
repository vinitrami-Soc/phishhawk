/* Sign in. Desktop: the card on the left, the product on the right; phones: the
   card only. Accounts are created by an admin on the Users screen. The logo and
   "About PhishHawk" lead back to the product page. */

import { useEffect, useState, type FormEvent } from 'react';
import { ArrowLeft, Eye, EyeOff, FileCheck2, ScrollText, Server } from 'lucide-react';
import { LiquidMetalButton } from '@/components/threeui/liquid-metal/LiquidMetalButton';
import { TextRoll } from '@/components/core/text-roll';
import { TextShimmer } from '@/components/core/text-shimmer';
import { SlidingNumber } from '@/components/core/sliding-number';
import { Spotlight } from '@/components/core/spotlight';
import { Cursor } from '@/components/core/cursor';
import { ImageComparison, ImageComparisonImage, ImageComparisonSlider } from '@/components/core/image-comparison';
import { ApiError, NETWORK_MESSAGE } from '@/api/errors';
import { Link, asset } from '@/app/router';
import { Panel } from '@/components/ui/ui';
import { usePicturesLoaded } from '@/hooks/usePicturesLoaded';

const FACTS = [
  { icon: Server, title: 'Runs on your server', text: 'Messages are analysed on the machine you run PhishHawk on.' },
  { icon: FileCheck2, title: 'Reported mail stays with you', text: 'With Offline analysis, no indicator is sent to an outside service.' },
  { icon: ScrollText, title: 'Every action is audited', text: 'Sign-ins, downloads and deletions are written to the audit log.' },
];

function Showcase() {
  const dark = asset('brand/report-dark.webp');
  const light = asset('brand/report-light.webp');
  const loaded = usePicturesLoaded([dark, light]);
  if (loaded) {
    return (
      <div className="grid gap-5">
        <Panel inner="overflow-hidden">
          <div className="relative aspect-[1180/1240] max-h-[70vh] w-full overflow-hidden rounded-[22px]">
            <ImageComparison className="h-full w-full" enableHover springOptions={{ bounce: 0.3 }}>
              <ImageComparisonImage src={dark} alt="The HTML report, dark theme" position="left" />
              <ImageComparisonImage src={light} alt="The HTML report, light theme" position="right" />
              <ImageComparisonSlider className="w-0.5 bg-white/50" />
            </ImageComparison>
            <Cursor attachToParent springConfig={{ bounce: 0.001 }}>
              <span className="rounded-full bg-black/80 px-2.5 py-1 text-xs text-white">Compare</span>
            </Cursor>
          </div>
        </Panel>
        <ul className="grid grid-cols-3 gap-3">
          {FACTS.map(({ title }) => (
            <li key={title} className="border-t border-line pt-3 text-center text-[13px] text-ink-dim">
              {title}
            </li>
          ))}
        </ul>
      </div>
    );
  }
  return (
    <Panel>
      <div className="relative grid gap-10 overflow-hidden rounded-[22px] px-10 py-12">
        <div className="pointer-events-none absolute -right-24 -top-24 h-72 w-72 rounded-full bg-brand/15 blur-3xl" aria-hidden="true" />
        <img src={asset('brand/phishhawk-mark.svg')} alt="" className="relative h-20 w-20" />
        <div className="relative">
          <h2 className="max-w-[18ch] text-[34px] font-semibold leading-[1.1] tracking-[-0.03em] text-ink">From a reported email to a verdict, with the evidence.</h2>
          <p className="mt-3 max-w-[46ch] text-[15px] text-ink-dim">
            Every analysis comes with a full HTML report: verdict, findings, indicators and ATT&amp;CK.
          </p>
        </div>
        <ul className="relative grid gap-3">
          {FACTS.map(({ icon: Icon, title, text }) => (
            <li key={title} className="flex items-start gap-4 rounded-2xl border border-line bg-raised/60 p-4">
              <span className="grid h-10 w-10 shrink-0 place-items-center rounded-xl border border-line bg-surface text-accent">
                <Icon className="h-[18px] w-[18px]" strokeWidth={1.5} />
              </span>
              <span>
                <span className="block text-sm font-medium text-ink">{title}</span>
                <span className="mt-0.5 block text-[13px] text-ink-muted">{text}</span>
              </span>
            </li>
          ))}
        </ul>
      </div>
    </Panel>
  );
}

export default function LoginScreen({ onSignIn, expired = false }: { onSignIn: (username: string, password: string) => Promise<void>; expired?: boolean }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [show, setShow] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [wait, setWait] = useState(0);

  useEffect(() => {
    if (wait <= 0) return;
    const t = setTimeout(() => setWait((w) => w - 1), 1000);
    return () => clearTimeout(t);
  }, [wait]);

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (busy || wait > 0) return;
    if (!username.trim() || !password) {
      setError('Enter your username and password.');
      return;
    }
    setBusy(true);
    setError(null);
    try {
      await onSignIn(username.trim(), password);
    } catch (e) {
      if (e instanceof ApiError && e.status === 429) {
        setWait(e.retryAfter ?? 30);
      } else if (e instanceof ApiError && e.status === 401) {
        setError('Wrong username or password.');
      } else {
        setError(e instanceof ApiError ? e.detail : NETWORK_MESSAGE);
      }
    } finally {
      setBusy(false);
    }
  }

  return (
    <main id="main" tabIndex={-1} className="relative mx-auto grid min-h-dvh max-w-[1280px] grid-cols-1 items-center gap-12 px-4 py-10 focus:outline-none md:px-8 lg:grid-cols-12 lg:gap-16">
      <section className="w-full max-w-[440px] justify-self-center lg:col-span-5">
        <Link href="/app/" className="mb-4 inline-flex items-center gap-1.5 rounded-full px-2 py-1 text-[13px] text-ink-muted transition-colors hover:text-ink">
          <ArrowLeft className="h-3.5 w-3.5" strokeWidth={1.75} aria-hidden="true" />
          About PhishHawk
        </Link>
        <Panel>
          <div className="relative overflow-hidden rounded-[22px] px-7 py-8 sm:px-9 sm:py-10">
            <Spotlight className="bg-accent/15 blur-3xl" size={240} />
            <Link href="/app/" aria-label="PhishHawk home" className="relative flex w-max items-center gap-3.5 rounded-2xl">
              <img src={asset('brand/phishhawk-mark.svg')} alt="" className="h-14 w-14" />
              <TextRoll className="text-2xl font-semibold tracking-[-0.018em] text-ink">PhishHawk</TextRoll>
            </Link>
            <p className="relative mt-5 text-[15px] text-ink-dim">Phishing triage for your security team, on your own server.</p>

            {expired && (
              <p className="relative mt-5 rounded-2xl border border-v-suspicious/30 bg-v-suspicious/10 px-4 py-3 text-sm text-ink" role="status">
                Your session has ended. Sign in again.
              </p>
            )}

            <form className="relative mt-7 grid grid-cols-1 gap-4" onSubmit={submit} noValidate>
              <div className="grid gap-1.5">
                <label htmlFor="login-username" className="text-[13px] font-medium text-ink-dim">
                  Username
                </label>
                <input
                  id="login-username"
                  autoComplete="username"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  className="h-12 rounded-[14px] border border-line-strong bg-raised px-4 text-[15px] text-ink focus:border-accent/60 focus:outline-none"
                />
              </div>
              <div className="grid gap-1.5">
                <label htmlFor="login-password" className="text-[13px] font-medium text-ink-dim">
                  Password
                </label>
                <div className="relative">
                  <input
                    id="login-password"
                    type={show ? 'text' : 'password'}
                    autoComplete="current-password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    className="h-12 w-full rounded-[14px] border border-line-strong bg-raised pl-4 pr-12 text-[15px] text-ink focus:border-accent/60 focus:outline-none"
                  />
                  <button
                    type="button"
                    onClick={() => setShow((s) => !s)}
                    aria-label={show ? 'Hide password' : 'Show password'}
                    className="absolute right-1.5 top-1.5 grid h-9 w-9 place-items-center rounded-full text-ink-muted hover:bg-hover hover:text-ink"
                  >
                    {show ? <EyeOff className="h-4 w-4" strokeWidth={1.5} /> : <Eye className="h-4 w-4" strokeWidth={1.5} />}
                  </button>
                </div>
              </div>

              <div className="mt-3 grid grid-cols-1 justify-items-center gap-3">
                <LiquidMetalButton type="submit" height={52} disabled={busy || wait > 0}>
                  Sign in
                </LiquidMetalButton>
                <div className="min-h-5 text-center text-sm" aria-live="polite">
                  {busy && <TextShimmer className="text-sm" duration={1.2}>Signing in</TextShimmer>}
                  {!busy && wait > 0 && (
                    <span className="inline-flex items-center gap-1 text-v-suspicious" role="alert">
                      Too many tries. Try again in <SlidingNumber value={wait} /> seconds.
                    </span>
                  )}
                  {!busy && wait === 0 && error && (
                    <span className="text-v-malicious" role="alert">
                      {error}
                    </span>
                  )}
                </div>
              </div>
            </form>
            {import.meta.env.DEV && (
              <p className="relative mt-2 rounded-xl border border-dashed border-line-strong px-3 py-2 text-center text-xs text-ink-muted">
                Development preview: any password works for an existing user.
              </p>
            )}
          </div>
        </Panel>
        <p className="mt-5 text-center text-[13px] text-ink-muted">No account? Ask your PhishHawk admin to add you on the Users page.</p>
        <p className="mt-3 text-center text-xs text-ink-muted">
          Signing in sets one cookie, only to keep you signed in.{' '}
          <Link href="/app/privacy" className="text-ink-dim underline underline-offset-2 hover:text-ink">
            Privacy and terms
          </Link>
          {' · '}
          <Link href="/app/help" className="text-ink-dim underline underline-offset-2 hover:text-ink">
            Help
          </Link>
        </p>
      </section>
      <section className="hidden lg:col-span-7 lg:block">
        <Showcase />
      </section>
    </main>
  );
}
