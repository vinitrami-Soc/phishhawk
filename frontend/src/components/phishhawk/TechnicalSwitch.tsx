/* "Show technical details", for someone on their own (app/technical.ts). */

import { useState } from 'react';
import type { Session } from '@/api/types';
import { rememberForTab, switchable, tabChoice, technicalView } from '@/app/technical';
import { Card, Switch } from '@/components/ui/ui';

export type TechnicalView = { technical: boolean; switchable: boolean; setTechnical: (next: boolean) => void };

export function useTechnicalView(session: Session): TechnicalView {
  const [choice, setChoice] = useState(tabChoice);
  return {
    technical: technicalView(session, choice),
    switchable: switchable(session),
    setTechnical: (next) => {
      rememberForTab(next);
      setChoice(next);
    },
  };
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
