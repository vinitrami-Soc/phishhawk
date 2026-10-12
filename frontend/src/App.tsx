/* App start, session, routes and the signed-in shell. The user and role come
   only from the server (useAuth). Every screen is loaded on demand. Privacy and
   Help can be read signed out too. */

import { lazy, Suspense, useEffect, useMemo } from 'react';
import { AnimatePresence, MotionConfig, motion } from 'motion/react';
import { Activity, Inbox, KeyRound, ListChecks, Mailbox, Network, ScrollText, Settings, Users } from 'lucide-react';
import { CommandBar, type CommandBarItem } from '@/components/threeui/command-bar/CommandBar';
import { ProgressiveBlur } from '@/components/core/progressive-blur';
import { TextShimmerWave } from '@/components/core/text-shimmer-wave';
import { BackToTop } from '@/components/phishhawk/BackToTop';
import { ThemeToggle } from '@/components/phishhawk/ThemeToggle';
import { ToastProvider } from '@/components/ui/toast';
import { Skeleton } from '@/components/ui/ui';
import { useAuth } from '@/app/useAuth';
import { Link, asset, navigate, usePath } from '@/app/router';
import { ADMIN_ONLY, PUBLIC_ROUTES, pageTitle, parseRoute } from '@/app/routes';
import { ROLE_LABEL } from '@/app/vocabulary';
import { NotFoundState, PermissionDeniedState, UnreachableState } from '@/screens/StateScreens';

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
        <Link href="/app/help" className="transition-colors hover:text-ink">
          Help
        </Link>
        <Link href="/app/privacy" className="transition-colors hover:text-ink">
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
  } else if ((auth.status === 'signed-out' || !session) && PUBLIC_ROUTES.includes(route.name)) {
    // signed out on Privacy or Help: the page, with the way back to signing in
    body = (
      <>
        <main id="main" tabIndex={-1} className="relative mx-auto w-full max-w-[1280px] px-4 pb-28 pt-6 focus:outline-none md:px-8">
          <header className="mb-10 flex items-center justify-between gap-4">
            <Link href="/app/login" className="flex items-center gap-2.5 text-ink">
              <img src={asset('brand/phishhawk-mark.svg')} alt="" className="h-8 w-8" />
              <span className="text-base font-semibold tracking-tight">PhishHawk</span>
            </Link>
            <Link
              href="/app/login"
              className="inline-flex h-10 items-center rounded-full border border-line-strong bg-raised px-4 text-sm font-medium text-ink transition-colors hover:bg-hover"
            >
              Sign in
            </Link>
          </header>
          <Suspense fallback={<PageFallback />}>{route.name === 'privacy' ? <PrivacyScreen /> : <HelpScreen />}</Suspense>
          <SiteFooter />
        </main>
        <BackToTop />
      </>
    );
  } else if (auth.status === 'signed-out' || !session) {
    body = (
      <Suspense fallback={null}>
        <LoginScreen
          expired={auth.status === 'signed-out' && auth.expired}
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
          onSignOut={signOut}
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
