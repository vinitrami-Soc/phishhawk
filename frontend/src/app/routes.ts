/* The routes, from the frontend build brief (section 7.1). In the dev server the
   page starts at "/", which is the same as "/app/". */

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
  | { name: 'not-found' };

const SIMPLE = ['audit', 'health', 'settings', 'users', 'tokens', 'mailboxes', 'login', 'privacy', 'help'] as const;

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
export const PUBLIC_ROUTES: Route['name'][] = ['privacy', 'help'];

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
  'not-found': 'Page not found',
};

/** The browser tab's title. Signed out, every page but the public ones is the sign-in page. */
export function pageTitle(route: Route, signedIn: boolean): string {
  const name = signedIn || PUBLIC_ROUTES.includes(route.name) ? TITLES[route.name] : TITLES.login;
  const numbered = signedIn && 'id' in route;
  return `${numbered ? `${name} ${route.id}` : name} · PhishHawk`;
}
