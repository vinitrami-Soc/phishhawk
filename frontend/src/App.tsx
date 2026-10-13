/* App start, session, routes and the signed-in shell. The user and role come
   only from the server (useAuth). Every screen is loaded on demand. Signed out,
   the start page is the product page, with Sign in at the top; the product
   page, Privacy and Help can be read signed out too. */

import { lazy, Suspense, useEffect, useLayoutEffect, useMemo, useRef } from 'react';
import { AnimatePresence, MotionConfig, motion } from 'motion/react';
import { Activity, Inbox, KeyRound, ListChecks, Mailbox, Network, ScrollText, Settings, Users } from 'lucide-react';
import { CommandBar, type CommandBarItem } from '@/components/threeui/command-bar/CommandBar';
import { ProgressiveBlur } from '@/components/core/progressive-blur';
import { TextShimmerWave } from '@/components/core/text-shimmer-wave';
import { BackToTop } from '@/components/phishhawk/BackToTop';
import { PublicFooter, PublicHeader } from '@/components/phishhawk/PublicChrome';
import { ThemeToggle } from '@/components/phishhawk/ThemeToggle';
import { ToastProvider } from '@/components/ui/toast';
import { Skeleton } from '@/components/ui/ui';
import { useAuth } from '@/app/useAuth';
import { Link, asset, navigate, usePath } from '@/app/router';
import { ADMIN_ONLY, pageTitle, parseRoute, signedOutView } from '@/app/routes';
import { ROLE_LABEL } from '@/app/vocabulary';
import { NotFoundState, PermissionDeniedState, UnreachableState } from '@/screens/StateScreens';

const LandingScreen = lazy(() => import('@/screens/LandingScreen'));
const LoginScreen = lazy(() => import('@/screens/LoginScreen'));
const TriageScreen = lazy(() => import('@/screens/TriageScreen'));
const QueueScreen = lazy(() => import('@/screens/QueueScreen'));
const AnalysisScreen = lazy(() => import('@/screens/AnalysisScreen'));
const BatchScreen = lazy(() => import('@/screens/BatchScreen'));
const CampaignsScreen = lazy(() => import('@/screens/CampaignsScreen'));
const CampaignScreen = lazy(() => import('@/screens/CampaignScreen'));
const AuditScreen = lazy(() => import('@/screens/AuditScreen'));
const HealthScreen = lazy(() => import('@/screens/HealthScreen'));
const SettingsScreen = lazy(() => import('@/screens/SettingsScreen'));
const UsersScreen = lazy(() => import('@/screens/UsersScreen'));
const TokensScreen = lazy(() => import('@/screens/TokensScreen'));
const MailboxesScreen = lazy(() => import('@/screens/MailboxesScreen'));
const PrivacyScreen = lazy(() => import('@/screens/PrivacyScreen'));
const HelpScreen = lazy(() => import('@/screens/HelpScreen'));

const icon = 'h-4 w-4';

function PageFallback() {
  return (
    <div className="grid gap-6" aria-busy="true" aria-label="Loading">
      <Skeleton className="h-10 w-64" />
      <Skeleton className="h-48 rounded-[28px]" />
      <Skeleton className="h-32 rounded-[28px]" />
    </div>
  );
}

function SiteFooter() {
  return (
    <footer className="mt-16 flex flex-wrap items-center justify-between gap-x-6 gap-y-2 border-t border-line pt-6 text-[13px] text-ink-muted print:hidden">
      <p>PhishHawk, run by your organisation.</p>
      <nav aria-label="About PhishHawk" className="flex gap-5">
        <Link href="/app/help" className="inline-flex min-h-8 items-center transition-colors hover:text-ink">
          Help
        </Link>
        <Link href="/app/privacy" className="inline-flex min-h-8 items-center transition-colors hover:text-ink">
          Privacy and terms
        </Link>
      </nav>
    </footer>
  );
}

/** The first thing a keyboard reaches: past the top bar, to the page's own content. */
function SkipLink() {
  return (
    <a
      href="#main"
      onClick={(event) => {
        const main = document.getElementById('main');
        if (!main) return;
        event.preventDefault();
        main.focus();
        main.scrollIntoView();
      }}
      className="sr-only rounded-full border border-line-strong bg-raised px-4 py-2 text-sm font-medium text-ink shadow-[var(--float-shadow)] focus:not-sr-only focus:fixed focus:left-4 focus:top-4 focus:z-[70]"
    >
      Skip to content
    </a>
  );
}

export default function App() {
  const { auth, signIn, signOut, retry } = useAuth();
  const path = usePath();
  const route = parseRoute(path);
  const session = auth.status === 'signed-in' ? auth.session : null;
  const expired = auth.status === 'signed-out' && auth.expired;
  // a session that ended on the start page shows the sign-in form, with why
  const view = expired && route.name === 'triage' ? 'login' : signedOutView(route);

  // signing out leads to the product page, before the sign-in form can show
  const signingOut = useRef(false);
  useLayoutEffect(() => {
    if (!signingOut.current || auth.status !== 'signed-out') return;
    signingOut.current = false;
    navigate('/app/');
  }, [auth.status]);

  // signed in on /app/login: go to the start page
  useEffect(() => {
    if (session && route.name === 'login') navigate('/app/', { replace: true });
  }, [session, route.name]);

  useEffect(() => {
    if (auth.status !== 'checking') document.title = pageTitle(parseRoute(path), Boolean(session));
  }, [path, session, auth.status]);

  const items = useMemo<CommandBarItem[]>(() => {
    const list: CommandBarItem[] = [
      { href: '/app/', label: 'Triage', icon: <Inbox className={icon} strokeWidth={1.5} /> },
      { href: '/app/analyses', label: 'Queue', icon: <ListChecks className={icon} strokeWidth={1.5} /> },
      { href: '/app/campaigns', label: 'Campaigns', icon: <Network className={icon} strokeWidth={1.5} /> },
      { href: '/app/audit', label: 'Audit', icon: <ScrollText className={icon} strokeWidth={1.5} /> },
    ];
    if (session?.role === 'admin') {
      list.push(
        { href: '/app/health', label: 'Health', icon: <Activity className={icon} strokeWidth={1.5} /> },
        { href: '/app/settings', label: 'Settings', icon: <Settings className={icon} strokeWidth={1.5} /> },
        { href: '/app/users', label: 'Users', icon: <Users className={icon} strokeWidth={1.5} /> },
        { href: '/app/tokens', label: 'Tokens', icon: <KeyRound className={icon} strokeWidth={1.5} /> },
        { href: '/app/mailboxes', label: 'Mailboxes', icon: <Mailbox className={icon} strokeWidth={1.5} /> },
      );
    }
    return list;
  }, [session?.role]);

  let body;
  if (auth.status === 'checking') {
    body = (
      <div className="grid min-h-dvh place-items-center">
        <TextShimmerWave className="text-base font-medium [--base-color:var(--text-muted)] [--base-gradient-color:var(--accent)]" duration={1.2}>
          Checking your session
        </TextShimmerWave>
      </div>
    );
  } else if (auth.status === 'unreachable') {
    body = (
      <main id="main" tabIndex={-1} className="relative mx-auto grid min-h-dvh max-w-[1280px] place-items-center px-4 focus:outline-none">
        <UnreachableState detail={auth.detail} onRetry={retry} />
      </main>
    );
  } else if ((!session && view === 'landing') || (session && route.name === 'about')) {
    // the product page: the start page signed out, and /app/about for everyone
    body = (
      <>
        <PublicHeader signedIn={Boolean(session)} onLanding />
        <main id="main" tabIndex={-1} className="relative w-full focus:outline-none">
          <Suspense fallback={<div className="mx-auto max-w-[1120px] px-4 pt-10 md:px-8"><PageFallback /></div>}>
            <LandingScreen signedIn={Boolean(session)} />
          </Suspense>
        </main>
        <PublicFooter signedIn={Boolean(session)} onLanding />
        <BackToTop />
      </>
    );
  } else if (!session && view === 'public') {
    // signed out on Privacy or Help: the page, under the product page's top bar
    body = (
      <>
        <PublicHeader />
        <main id="main" tabIndex={-1} className="relative mx-auto w-full max-w-[1280px] px-4 pt-10 focus:outline-none md:px-8">
          <Suspense fallback={<PageFallback />}>{route.name === 'privacy' ? <PrivacyScreen /> : <HelpScreen />}</Suspense>
        </main>
        <PublicFooter />
        <BackToTop />
      </>
    );
  } else if (auth.status === 'signed-out' || !session) {
    body = (
      <Suspense fallback={null}>
        <LoginScreen
          expired={expired}
          onSignIn={async (username, password) => {
            await signIn(username, password);
            if (parseRoute(window.location.pathname).name === 'login') navigate('/app/', { replace: true });
          }}
        />
      </Suspense>
    );
  } else {
    const isAdmin = session.role === 'admin';
    let screen;
    if (ADMIN_ONLY.includes(route.name) && !isAdmin) screen = <PermissionDeniedState />;
    else if (route.name === 'triage' || route.name === 'login') screen = <TriageScreen />;
    else if (route.name === 'queue') screen = <QueueScreen session={session} />;
    else if (route.name === 'analysis') screen = <AnalysisScreen id={route.id} session={session} />;
    else if (route.name === 'batch') screen = <BatchScreen id={route.id} />;
    else if (route.name === 'campaigns') screen = <CampaignsScreen />;
    else if (route.name === 'campaign') screen = <CampaignScreen id={route.id} />;
    else if (route.name === 'audit') screen = <AuditScreen session={session} />;
    else if (route.name === 'health') screen = <HealthScreen />;
    else if (route.name === 'settings') screen = <SettingsScreen />;
    else if (route.name === 'users') screen = <UsersScreen session={session} />;
    else if (route.name === 'tokens') screen = <TokensScreen />;
    else if (route.name === 'mailboxes') screen = <MailboxesScreen />;
    else if (route.name === 'privacy') screen = <PrivacyScreen />;
    else if (route.name === 'help') screen = <HelpScreen />;
    else screen = <NotFoundState />;

    body = (
      <>
        <CommandBar
          items={items}
          current={path === '/' ? '/app/' : path}
          homeHref="/app/"
          mark={<img src={asset('brand/phishhawk-mark.svg')} alt="" />}
          user={{ name: session.username, role: ROLE_LABEL[session.role] ?? session.role }}
          onNavigate={(href) => navigate(href)}
          onSignOut={() => {
            signingOut.current = true;
            void signOut();
          }}
          primaryCount={4}
        />
        <ProgressiveBlur direction="top" blurLayers={6} blurIntensity={0.6} className="pointer-events-none fixed inset-x-0 top-0 z-30 h-12 print:hidden" />
        <main id="main" tabIndex={-1} className="relative mx-auto w-full max-w-[1280px] px-4 pb-10 pt-6 focus:outline-none md:px-6 lg:px-8">
          <AnimatePresence mode="wait">
            <motion.div
              key={'id' in route ? `${route.name}-${route.id}` : route.name}
              initial={{ opacity: 0, y: 6 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0 }}
              transition={{ duration: 0.18, ease: [0.32, 0.72, 0, 1] }}
            >
              <Suspense fallback={<PageFallback />}>{screen}</Suspense>
            </motion.div>
          </AnimatePresence>
        </main>
        <div className="mx-auto w-full max-w-[1280px] px-4 pb-28 md:px-6 lg:px-8">
          <SiteFooter />
        </div>
        <BackToTop raised={route.name === 'analysis'} />
      </>
    );
  }

  return (
    <MotionConfig reducedMotion="user">
      <ToastProvider>
        <SkipLink />
        <div className="ph-aura" aria-hidden="true" />
        <div className="relative min-h-dvh">{body}</div>
        {!session && (
          <div className="print:hidden">
            <ThemeToggle />
          </div>
        )}
      </ToastProvider>
    </MotionConfig>
  );
}
