/* "Show technical details", for someone on their own (app/technical.ts). */

import { useSyncExternalStore } from 'react';
import type { Session } from '@/api/types';
import { onTabChoice, rememberForTab, switchable, tabChoice, technicalView } from '@/app/technical';
import { Card, Switch } from '@/components/ui/ui';

export type TechnicalView = { technical: boolean; switchable: boolean; setTechnical: (next: boolean) => void };

/** Every page and the top bar read the same choice, so turning the switch changes them together.
    Signed out (no session), everything is technical. */
export function useTechnicalView(session: Pick<Session, 'workspace'> | null): TechnicalView {
  const choice = useSyncExternalStore(onTabChoice, tabChoice);
  const who = session ?? { workspace: null };
  return { technical: technicalView(who, choice), switchable: switchable(who), setTechnical: rememberForTab };
}

export function TechnicalSwitch({ view }: { view: TechnicalView }) {
  if (!view.switchable) return null;
  return (
    <Card className="px-5 py-4 sm:px-6">
      <Switch
        checked={view.technical}
        onChange={view.setTechnical}
        label="Show technical details"
        description="Indicators, authentication checks, ATT&CK, the full report and downloads."
      />
    </Card>
  );
}
