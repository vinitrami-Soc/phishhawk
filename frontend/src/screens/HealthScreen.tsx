/* Health: exactly what /healthz returns. */

import { useEffect, useState } from 'react';
import { AnimatedNumber } from '@/components/core/animated-number';
import { getHealth } from '@/api/client';
import { ApiError, NETWORK_MESSAGE, isAbort } from '@/api/errors';
import type { Health } from '@/api/types';
import { Card, ErrorState, PageHeader, Skeleton, Time } from '@/components/ui/ui';

function Tile({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <Card className="grid gap-2 p-6">
      <p className="text-xs text-ink-muted">{label}</p>
      <div className="text-2xl font-semibold tracking-tight text-ink">{children}</div>
    </Card>
  );
}

export default function HealthScreen() {
  const [health, setHealth] = useState<Health | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    const controller = new AbortController();
    setError(null);
    getHealth(controller.signal)
      .then(setHealth)
      .catch((e) => !isAbort(e) && setError(e instanceof ApiError ? e.detail : NETWORK_MESSAGE));
    return () => controller.abort();
  }, [attempt]);

  return (
    <div className="grid grid-cols-1 gap-8">
      <PageHeader eyebrow="Health" title="Server health" description="What the PhishHawk server reports about itself." />
      {error ? (
        <ErrorState detail={error} onRetry={() => setAttempt((a) => a + 1)} />
      ) : !health ? (
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {[0, 1, 2, 3, 4].map((i) => (
            <Skeleton key={i} className="h-28 rounded-[20px]" />
          ))}
        </div>
      ) : (
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          <Tile label="Status">
            <span className="inline-flex items-center gap-2">
              <span className={health.status === 'ok' ? 'h-2 w-2 rounded-full bg-ok' : 'h-2 w-2 rounded-full bg-v-suspicious'} aria-hidden="true" />
              {health.status}
            </span>
          </Tile>
          <Tile label="Version">
            <span className="font-mono text-xl">{health.version}</span>
          </Tile>
          <Tile label="Jobs waiting">
            <AnimatedNumber value={health.queue} springOptions={{ bounce: 0, duration: 900 }} />
          </Tile>
          <Tile label="Free disk">
            <span className="inline-flex items-baseline gap-1.5">
              <AnimatedNumber value={health.disk_free_mb} springOptions={{ bounce: 0, duration: 900 }} />
              <span className="text-sm font-normal text-ink-muted">MB</span>
            </span>
          </Tile>
          <Tile label="Last heartbeat">
            <span className="text-base font-medium">{health.last_heartbeat ? <Time iso={health.last_heartbeat} /> : 'No heartbeat yet'}</span>
          </Tile>
        </div>
      )}
    </div>
  );
}
