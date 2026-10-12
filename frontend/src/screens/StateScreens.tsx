/* Not found, permission denied and server unreachable: one sentence, one action. */

import type { ReactNode } from 'react';
import { CloudOff, Compass, Lock } from 'lucide-react';
import { navigate } from '@/app/router';
import { Button } from '@/components/ui/ui';

function StateBlock({ icon, title, detail, action }: { icon: ReactNode; title: string; detail?: string; action: ReactNode }) {
  return (
    <div className="mx-auto grid max-w-md justify-items-center gap-4 py-24 text-center">
      <div className="grid h-12 w-12 place-items-center rounded-2xl border border-line bg-surface text-ink-dim">{icon}</div>
      <div>
        <h1 className="text-xl font-semibold tracking-tight text-ink">{title}</h1>
        {detail && <p className="mt-1.5 text-sm text-ink-dim">{detail}</p>}
      </div>
      {action}
    </div>
  );
}

export function NotFoundState() {
  return (
    <StateBlock
      icon={<Compass className="h-5 w-5" strokeWidth={1.5} />}
      title="This page does not exist."
      action={<Button onClick={() => navigate('/app/')}>Go to Triage</Button>}
    />
  );
}

export function PermissionDeniedState() {
  return (
    <StateBlock
      icon={<Lock className="h-5 w-5" strokeWidth={1.5} />}
      title="Only an admin can open this page."
      action={<Button onClick={() => navigate('/app/')}>Go to Triage</Button>}
    />
  );
}

export function UnreachableState({ detail, onRetry }: { detail: string; onRetry: () => void }) {
  return (
    <StateBlock
      icon={<CloudOff className="h-5 w-5" strokeWidth={1.5} />}
      title="PhishHawk is not answering."
      detail={detail}
      action={<Button onClick={onRetry}>Try again</Button>}
    />
  );
}
