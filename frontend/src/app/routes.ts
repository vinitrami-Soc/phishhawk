/* The routes, from the frontend build brief (section 7.1). In the dev server the
   page starts at "/", which is the same as "/app/". Signed out, "/app/" is the
   product page; signed in, it is Triage. The product page is also at /app/about. */

export type Route =
  | { name: 'triage' }
  | { name: 'queue' }
  | { name: 'analysis'; id: number }
  | { name: 'batch'; id: number }
  | { name: 'campaigns' }
  | { name: 'campaign'; id: number }
  | { name: 'audit' }
  | { name: 'health' }
  | { name: 'settings' }
  | { name: 'users' }
  | { name: 'tokens' }
  | { name: 'mailboxes' }
  | { name: 'login' }
  | { name: 'privacy' }
  | { name: 'help' }
  | { name: 'about' }
  | { name: 'not-found' };

const SIMPLE = ['audit', 'health', 'settings', 'users', 'tokens', 'mailboxes', 'login', 'privacy', 'help', 'about'] as const;

export function parseRoute(pathname: string): Route {
  const path = pathname.replace(/\/+$/, '') || '/';
  if (path === '/' || path === '/app') return { name: 'triage' };
  if (path === '/app/analyses') return { name: 'queue' };
  const analysis = path.match(/^\/app\/analyses\/(\d{1,12})$/);
  if (analysis) return { name: 'analysis', id: Number(analysis[1]) };
  const batch = path.match(/^\/app\/batches\/(\d{1,12})$/);
  if (batch) return { name: 'batch', id: Number(batch[1]) };
  if (path === '/app/campaigns') return { name: 'campaigns' };
  const campaign = path.match(/^\/app\/campaigns\/(\d{1,12})$/);
  if (campaign) return { name: 'campaign', id: Number(campaign[1]) };
  for (const name of SIMPLE) {
    if (path === `/app/${name}`) return { name };
  }
  return { name: 'not-found' };
}

export const ADMIN_ONLY: Route['name'][] = ['health', 'settings', 'users', 'tokens', 'mailboxes'];

/** Pages anyone can read, signed in or not. */
export const PUBLIC_ROUTES: Route['name'][] = ['about', 'privacy', 'help'];

/** What a signed-out visitor sees: the product page at the start, a public page, or the sign-in form. */
export function signedOutView(route: Route): 'landing' | 'public' | 'login' {
  if (route.name === 'triage' || route.name === 'about') return 'landing';
  return PUBLIC_ROUTES.includes(route.name) ? 'public' : 'login';
}

const TITLES: Record<Route['name'], string> = {
  triage: 'Triage',
  queue: 'Queue',
  analysis: 'Analysis',
  batch: 'Batch',
  campaigns: 'Campaigns',
  campaign: 'Campaign',
  audit: 'Audit log',
  health: 'Health',
  settings: 'Settings',
  users: 'Users',
  tokens: 'API tokens',
  mailboxes: 'Mailboxes',
  login: 'Sign in',
  privacy: 'Privacy and terms',
  help: 'Help',
  about: 'Phishing email triage',
  'not-found': 'Page not found',
};

/** The browser tab's title. Signed out, the start page is the product page and
    every page but the public ones is the sign-in page. */
export function pageTitle(route: Route, signedIn: boolean): string {
  const view = signedOutView(route);
  const name = signedIn ? TITLES[route.name] : view === 'landing' ? TITLES.about : view === 'public' ? TITLES[route.name] : TITLES.login;
  const numbered = signedIn && 'id' in route;
  return `${numbered ? `${name} ${route.id}` : name} · PhishHawk`;
}
