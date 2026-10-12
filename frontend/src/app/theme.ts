/* Light and dark theme. The theme is the `data-theme` attribute on <html>;
   every colour comes from the tokens in src/styles/tokens.css. The viewer's
   choice is kept in this browser only (it is a display preference, not data),
   and without a choice the page follows the system setting. Switching runs a
   circular reveal from the toggle where the browser supports view
   transitions, and a plain switch otherwise or with reduced motion. */

import { useSyncExternalStore } from 'react';

export type Theme = 'dark' | 'light';

const STORAGE_KEY = 'phishhawk-theme';
const listeners = new Set<() => void>();

export function pickTheme(saved: string | null, systemPrefersDark: boolean): Theme {
  if (saved === 'dark' || saved === 'light') return saved;
  return systemPrefersDark ? 'dark' : 'light';
}

/** Distance from (x, y) to the farthest corner of a width x height screen. */
export function revealRadius(x: number, y: number, width: number, height: number): number {
  return Math.hypot(Math.max(x, width - x), Math.max(y, height - y));
}

function savedTheme(): string | null {
  try {
    return window.localStorage.getItem(STORAGE_KEY);
  } catch {
    return null;
  }
}

function saveTheme(theme: Theme) {
  try {
    window.localStorage.setItem(STORAGE_KEY, theme);
  } catch {
    // private mode or blocked storage: the choice lasts for this page only
  }
}

function applyTheme(theme: Theme) {
  const root = document.documentElement;
  root.dataset.theme = theme;
  root.style.colorScheme = theme;
  listeners.forEach((notify) => notify());
}

export function currentTheme(): Theme {
  return document.documentElement.dataset.theme === 'light' ? 'light' : 'dark';
}

/** Call once before the first render, so the page never flashes the other theme. */
export function startTheme() {
  applyTheme(pickTheme(savedTheme(), window.matchMedia('(prefers-color-scheme: dark)').matches));
}

/** Switch the theme; `from` is the point the reveal grows from (the toggle). */
export function setTheme(next: Theme, from?: { x: number; y: number }) {
  saveTheme(next);
  if (next === currentTheme()) return;
  const reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  if (!document.startViewTransition || reduced) {
    applyTheme(next);
    return;
  }
  const x = from?.x ?? 0;
  const y = from?.y ?? window.innerHeight;
  const transition = document.startViewTransition(() => applyTheme(next));
  transition.ready
    .then(() => {
      const r = revealRadius(x, y, window.innerWidth, window.innerHeight);
      document.documentElement.animate(
        { clipPath: [`circle(0px at ${x}px ${y}px)`, `circle(${r}px at ${x}px ${y}px)`] },
        { duration: 560, easing: 'cubic-bezier(0.32, 0.72, 0, 1)', pseudoElement: '::view-transition-new(root)' },
      );
    })
    .catch(() => {
      // the transition was skipped; the theme is already applied
    });
}

function subscribe(notify: () => void) {
  listeners.add(notify);
  return () => listeners.delete(notify);
}

export function useTheme(): Theme {
  return useSyncExternalStore(subscribe, currentTheme, () => 'dark');
}
