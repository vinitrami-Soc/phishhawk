/* <CommandBar />: PhishHawk's top navigation, built from ThreeUI
   <AnimatedTopDock variant="modern" proximity={122} spring={0.19}
   damping={0.70} widthGrowth={17} heightGrowth={16} drop={3.5} />.

   The packaged component is a demo: its wordmark ("Lumina"), its five items
   and its two buttons are fixed, with no props to change them, and its items
   are buttons that only highlight themselves. This keeps its markup classes,
   its CSS and its spring controller unchanged, and fills it with PhishHawk's
   routes, the user chip and "Sign out".

   Routing stays the app's: items are real <a href> links and onNavigate is
   called on a plain left click so a client router can take over.

   Past the first primaryCount items, the pages are in "More", at every width:
   nine pages, the user and "Sign out" are wider than the bar on most screens.
   More also says who is signed in and with which role, which the bar has no
   room for on phones and tablets. */

import { useEffect, useId, useRef, useState, type MouseEvent, type ReactNode, type RefObject } from 'react';
import useClickOutside from '../../../hooks/useClickOutside';
import { createTopDockController } from './topDockController';
import { ThemeToggle } from '../../phishhawk/ThemeToggle';
import './command-bar.css';

export type CommandBarItem = {
  href: string;
  label: string;
  /** A 16px stroke icon (for example a lucide-react icon). */
  icon: ReactNode;
};

export type CommandBarProps = {
  items: CommandBarItem[];
  /** href of the current page, compared exactly or as a prefix ("/app/analyses" matches "/app/analyses/12"). */
  current: string;
  homeHref: string;
  /** The PhishHawk mark: an <img> of the logo, or an SVG. */
  mark: ReactNode;
  user?: { name: string; role: string };
  onNavigate?: (href: string) => void;
  onSignOut?: () => void;
  signOutLabel?: string;
  /** How many items stay in the bar; the rest go into "More". */
  primaryCount?: number;
};

// The configured usage: proximity 122, spring 0.19, damping 0.70,
// widthGrowth 17, heightGrowth 16, drop 3.5 (the package defaults).
const DOCK = { proximity: 122, spring: 0.19, damping: 0.7, widthGrowth: 17, heightGrowth: 16, drop: 3.5 };

function isCurrent(current: string, href: string, homeHref: string) {
  if (href === homeHref) return current === homeHref;
  return current === href || current.startsWith(href.replace(/\/$/, '') + '/');
}

export function CommandBar({
  items,
  current,
  homeHref,
  mark,
  user,
  onNavigate,
  onSignOut,
  signOutLabel = 'Sign out',
  primaryCount = 4,
}: CommandBarProps) {
  const navRef = useRef<HTMLElement>(null);
  const moreRef = useRef<HTMLDivElement>(null);
  const [menuOpen, setMenuOpen] = useState(false);
  const menuId = useId();
  const itemsKey = items.map((i) => i.href).join('|');

  // Restart the physics when the set of items changes (for example after a
  // role change), so every item is measured again.
  useEffect(() => {
    const nav = navRef.current;
    if (!nav) return;
    return createTopDockController(nav, () => ({ ...DOCK, axis: 'x', distribute: false, lockTrack: true }));
  }, [itemsKey]);

  useClickOutside(moreRef as RefObject<HTMLDivElement>, () => setMenuOpen(false));
  useEffect(() => {
    if (!menuOpen) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setMenuOpen(false);
    };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [menuOpen]);

  const follow = (href: string) => (e: MouseEvent<HTMLAnchorElement>) => {
    if (!onNavigate || e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
    e.preventDefault();
    setMenuOpen(false);
    onNavigate(href);
  };

  const overflow = items.slice(primaryCount);

  return (
    <div className="animated-top-dock-component atd-modern ph-commandbar" data-dock-frame>
      <header className="atd-modern__bar">
        <a className="atd-modern__brand" href={homeHref} onClick={follow(homeHref)}>
          <span className="atd-modern__mark" aria-hidden="true">
            {mark}
          </span>
          <span className="atd-modern__word">PhishHawk</span>
        </a>
        <nav
          ref={navRef}
          className="atd-modern__dock"
          aria-label="Primary"
          data-dock-state="idle"
          data-dock-max="0.00"
        >
          {items.map((item, index) => (
            <a
              key={item.href}
              className="atd-modern__item"
              data-dock-item
              data-overflow={index >= primaryCount ? 'true' : undefined}
              href={item.href}
              aria-current={isCurrent(current, item.href, homeHref) ? 'page' : undefined}
              onClick={follow(item.href)}
            >
              <span className="atd-modern__icon" aria-hidden="true">
                {item.icon}
              </span>
              <span>{item.label}</span>
            </a>
          ))}
        </nav>
        <div className="atd-modern__actions">
          {(overflow.length > 0 || user) && (
            <div ref={moreRef} className="ph-commandbar__more-wrap">
              <button
                type="button"
                className="atd-modern__ghost ph-commandbar__more"
                aria-expanded={menuOpen}
                aria-controls={menuId}
                onClick={() => setMenuOpen((open) => !open)}
              >
                More
              </button>
              {menuOpen && (
                <div id={menuId} className="ph-commandbar__menu">
                  {user && (
                    <p className="ph-commandbar__menu-user">
                      Signed in as <strong>{user.name}</strong>
                      <span className="ph-commandbar__role">{user.role}</span>
                    </p>
                  )}
                  {overflow.map((item) => (
                    <a
                      key={item.href}
                      href={item.href}
                      aria-current={isCurrent(current, item.href, homeHref) ? 'page' : undefined}
                      onClick={follow(item.href)}
                    >
                      <span aria-hidden="true">{item.icon}</span>
                      {item.label}
                    </a>
                  ))}
                </div>
              )}
            </div>
          )}
          {user && (
            <span className="ph-commandbar__user">
              {user.name}
              <span className="ph-commandbar__role">{user.role}</span>
            </span>
          )}
          {onSignOut && (
            <button type="button" className="atd-modern__cta" onClick={onSignOut}>
              <span>{signOutLabel}</span>
              <svg viewBox="0 0 16 16" aria-hidden="true">
                <path d="M3.2 8h9.1M8.6 4.3 12.4 8l-3.8 3.7" />
              </svg>
            </button>
          )}
          <ThemeToggle className="ph-commandbar__toggle" />
        </div>
      </header>
    </div>
  );
}
