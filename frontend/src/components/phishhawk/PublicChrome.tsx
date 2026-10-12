/* The top bar and the footer of the pages a visitor reads before signing in:
   the product page, Help and Privacy. The bar floats like the console's command
   bar and takes its colours; the footer is a site map in four columns. Links to
   the product page's sections scroll in place on that page and open it
   everywhere else. */

import type { MouseEvent, ReactNode } from 'react';
import { useReducedMotion } from 'motion/react';
import { ArrowRight } from 'lucide-react';
import { AnimatedBackground } from '@/components/core/animated-background';
import { TextRoll } from '@/components/core/text-roll';
import { Link, asset } from '@/app/router';
import { cn } from '@/lib/utils';

export const SECTIONS = [
  { id: 'how', label: 'How it works' },
  { id: 'checks', label: 'What it checks' },
  { id: 'ways', label: 'Ways to use' },
  { id: 'faq', label: 'FAQ' },
] as const;

/** Scrolls to a section of the product page and puts its name in the address bar. */
export function useScrollToSection() {
  const reduce = useReducedMotion();
  return (event: MouseEvent<HTMLAnchorElement>, id: string) => {
    const target = document.getElementById(id);
    if (!target) return;
    event.preventDefault();
    target.scrollIntoView({ behavior: reduce ? 'auto' : 'smooth', block: 'start' });
    window.history.replaceState(null, '', `#${id}`);
  };
}

/** A link to a section of the product page: in place on that page, by address anywhere else. */
export function SectionLink({ id, onLanding, className, children, ...rest }: { id: string; onLanding: boolean; className?: string; children: ReactNode; 'data-id'?: string }) {
  const scrollTo = useScrollToSection();
  if (onLanding) {
    return (
      <a href={`#${id}`} onClick={(event) => scrollTo(event, id)} className={className} {...rest}>
        {children}
      </a>
    );
  }
  return (
    <Link href={`/app/about#${id}`} className={className} {...rest}>
      {children}
    </Link>
  );
}

/** The way into the console: Sign in, or Open console for someone already signed in. */
export function EnterLink({ signedIn, className }: { signedIn: boolean; className?: string }) {
  return (
    <Link
      href={signedIn ? '/app/' : '/app/login'}
      className={cn(
        'group inline-flex h-10 shrink-0 items-center gap-1.5 rounded-full px-4 text-sm font-medium text-[var(--pill-active-ink)] shadow-[var(--float-shadow)] transition-transform duration-300 ease-[cubic-bezier(0.32,0.72,0,1)] [background:var(--pill-active-bg)] active:scale-[0.98]',
        className,
      )}
    >
      {signedIn ? 'Open console' : 'Sign in'}
      <ArrowRight className="h-4 w-4 transition-transform duration-300 group-hover:translate-x-0.5 motion-reduce:transition-none" strokeWidth={1.75} aria-hidden="true" />
    </Link>
  );
}

function Brand({ onLanding }: { onLanding: boolean }) {
  const scrollTo = useScrollToSection();
  const inner = (
    <>
      <img src={asset('brand/phishhawk-mark.svg')} alt="" className="h-9 w-9 rounded-[10px] shadow-[0_6px_18px_-8px_var(--brand)]" />
      <TextRoll className="text-[15px] font-semibold tracking-[-0.01em] text-ink">PhishHawk</TextRoll>
    </>
  );
  const className = 'flex shrink-0 items-center gap-2.5 rounded-full py-1 pl-1 pr-2';
  if (onLanding) {
    return (
      <a href="#top" aria-label="PhishHawk home" onClick={(event) => scrollTo(event, 'top')} className={className}>
        {inner}
      </a>
    );
  }
  return (
    <Link href="/app/about" aria-label="PhishHawk home" className={className}>
      {inner}
    </Link>
  );
}

export function PublicHeader({ signedIn = false, onLanding = false }: { signedIn?: boolean; onLanding?: boolean }) {
  return (
    <header className="sticky top-0 z-40 px-3 pt-3 print:hidden sm:px-4">
      <div className="mx-auto flex h-[60px] max-w-[1120px] items-center justify-between gap-3 rounded-full border border-line-strong pl-2 pr-2 backdrop-blur-xl [background:var(--bar-bg)] shadow-[var(--bar-shadow)] sm:pl-3">
        <Brand onLanding={onLanding} />
        <nav aria-label="Product page" className="hidden md:block">
          <div className="flex items-center gap-1">
            <AnimatedBackground enableHover className="rounded-full bg-hover" transition={{ type: 'spring', bounce: 0.15, duration: 0.35 }}>
              {SECTIONS.map(({ id, label }) => (
                <SectionLink
                  key={id}
                  data-id={id}
                  id={id}
                  onLanding={onLanding}
                  className="h-9 items-center rounded-full px-3.5 text-[13px] font-medium text-ink-dim transition-colors duration-300 hover:text-ink"
                >
                  {label}
                </SectionLink>
              ))}
            </AnimatedBackground>
          </div>
        </nav>
        <EnterLink signedIn={signedIn} />
      </div>
    </header>
  );
}

type FooterLink = { label: string; href?: string; section?: string };

const COLUMNS: { title: string; links: FooterLink[] }[] = [
  {
    title: 'Product',
    links: [
      { label: 'About PhishHawk', section: 'top' },
      { label: 'How it works', section: 'how' },
      { label: 'What it checks', section: 'checks' },
      { label: 'Built for sensitive mail', section: 'trust' },
    ],
  },
  {
    title: 'Get started',
    links: [
      { label: 'Sign in', href: '/app/login' },
      { label: 'Analysis queue', href: '/app/analyses' },
      { label: 'Campaigns', href: '/app/campaigns' },
      { label: 'Audit log', href: '/app/audit' },
    ],
  },
  {
    title: 'Learn',
    links: [
      { label: 'Help', href: '/app/help' },
      { label: 'What the verdicts mean', section: 'verdicts' },
      { label: 'Questions and answers', section: 'faq' },
      { label: 'Privacy and terms', href: '/app/privacy' },
    ],
  },
  {
    title: 'For admins',
    links: [
      { label: 'Users', href: '/app/users' },
      { label: 'API tokens', href: '/app/tokens' },
      { label: 'Report mailboxes', href: '/app/mailboxes' },
      { label: 'Health', href: '/app/health' },
    ],
  },
];

const footerLink = 'text-sm text-ink-dim transition-colors duration-200 hover:text-ink';

export function PublicFooter({ signedIn = false, onLanding = false }: { signedIn?: boolean; onLanding?: boolean }) {
  return (
    <footer className="relative mt-24 border-t border-line bg-surface print:hidden">
      <div className="mx-auto w-full max-w-[1120px] px-4 pb-28 pt-14 md:px-8">
        <div className="flex flex-wrap items-center justify-between gap-6 border-b border-line pb-10">
          <div className="flex items-center gap-3.5">
            <img src={asset('brand/phishhawk-mark.svg')} alt="" className="h-11 w-11 rounded-xl" />
            <div>
              <p className="text-base font-semibold tracking-[-0.01em] text-ink">PhishHawk</p>
              <p className="text-[13px] text-ink-muted">Phishing triage, on a server your organisation runs.</p>
            </div>
          </div>
          <EnterLink signedIn={signedIn} />
        </div>

        <div className="grid grid-cols-2 gap-x-6 gap-y-10 pt-10 md:grid-cols-4">
          {COLUMNS.map(({ title, links }) => (
            <nav key={title} aria-label={title}>
              <h2 className="text-[12px] font-semibold uppercase tracking-[0.14em] text-ink">{title}</h2>
              <ul className="mt-5 grid gap-3.5">
                {links.map(({ label, href, section }) => (
                  <li key={label}>
                    {section ? (
                      <SectionLink id={section} onLanding={onLanding} className={footerLink}>
                        {label}
                      </SectionLink>
                    ) : (
                      <Link href={href ?? '/app/'} className={footerLink}>
                        {label}
                      </Link>
                    )}
                  </li>
                ))}
              </ul>
            </nav>
          ))}
        </div>

        <div className="mt-12 flex flex-wrap items-center justify-between gap-x-6 gap-y-2 border-t border-line pt-6 text-[13px] text-ink-muted">
          <p>Run by your organisation, on your own server.</p>
          <p>Offline by default · Every action audited · Open source, MIT licence</p>
        </div>
      </div>
    </footer>
  );
}
