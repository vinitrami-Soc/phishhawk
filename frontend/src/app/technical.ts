/* Technical pages or simple ones (docs/superpowers/specs/2026-10-26-simple-view-design.md).
   An organization always sees the technical pages. Someone on their own sees the
   simple ones until they turn on "Show technical details". The choice lasts while
   this tab is open: browser storage is kept for the theme alone
   (src/__tests__/rules.test.ts), so a reload starts simple again. */

import type { Session } from '@/api/types';

type WithWorkspace = Pick<Session, 'workspace'>;

let chosen = false;

/** Only someone on their own has the switch. */
export function switchable(session: WithWorkspace): boolean {
  return session.workspace?.kind === 'individual';
}

export function technicalView(session: WithWorkspace, choice: boolean): boolean {
  return !switchable(session) || choice;
}

/** This tab's choice: off until the switch is turned on. */
export function tabChoice(): boolean {
  return chosen;
}

export function rememberForTab(next: boolean): void {
  chosen = next;
}
