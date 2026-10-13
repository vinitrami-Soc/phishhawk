/* The audit log, 100 entries a page, newest first. Actor and details are shown
   exactly as the server records them, as text. */

import { useEffect, useState } from 'react';
import { listAudit } from '@/api/client';
import { ApiError, NETWORK_MESSAGE, isAbort } from '@/api/errors';
import type { AuditEntry, Session } from '@/api/types';
import { auditLabel } from '@/app/vocabulary';
import { Button, Card, EmptyState, ErrorState, PageHeader, SkeletonRows, Time } from '@/components/ui/ui';

const PAGE = 100;

function Details({ details }: { details: Record<string, unknown> }) {
  const entries = Object.entries(details ?? {});
  if (entries.length === 0) return <span className="text-ink-muted">—</span>;
  return (
    <dl className="grid gap-0.5 font-mono text-xs">
      {entries.map(([key, value]) => (
        <div key={key} className="flex min-w-0 gap-1.5">
          <dt className="shrink-0 text-ink-muted">{key}:</dt>
          <dd className="min-w-0 break-all text-ink-dim">{typeof value === 'string' ? value : JSON.stringify(value)}</dd>
        </div>
      ))}
    </dl>
  );
}

const objectText = (e: AuditEntry) => [e.object_type, e.object_id].filter(Boolean).join(' ') || '—';

export default function AuditScreen({ session }: { session: Session }) {
  const [rows, setRows] = useState<AuditEntry[]>([]);
  const [phase, setPhase] = useState<'loading' | 'ready' | 'loading-more' | 'error'>('loading');
  const [end, setEnd] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    const controller = new AbortController();
    setPhase('loading');
    setError(null);
    listAudit(0, controller.signal)
      .then((list) => {
        setRows(list);
        setEnd(list.length < PAGE);
        setPhase('ready');
      })
      .catch((e) => {
        if (isAbort(e)) return;
        setError(e instanceof ApiError ? e.detail : NETWORK_MESSAGE);
        setPhase('error');
      });
    return () => controller.abort();
  }, [attempt]);

  async function loadMore() {
    setPhase('loading-more');
    try {
      const more = await listAudit(rows.length);
      setRows((r) => [...r, ...more]);
      setEnd(more.length < PAGE);
    } catch (e) {
      setError(e instanceof ApiError ? e.detail : NETWORK_MESSAGE);
    } finally {
      setPhase('ready');
    }
  }

  return (
    <div className="grid grid-cols-1 gap-8">
      <PageHeader
        eyebrow="Audit"
        title="Audit log"
        description={session.role === 'admin' ? 'Who did what, and when. Newest first.' : 'Who did what, and when. Newest first. You see your own actions.'}
      />
      {phase === 'loading' ? (
        <SkeletonRows rows={8} />
      ) : phase === 'error' ? (
        <ErrorState detail={error ?? NETWORK_MESSAGE} onRetry={() => setAttempt((a) => a + 1)} />
      ) : rows.length === 0 ? (
        <EmptyState title="Nothing has been recorded yet." />
      ) : (
        <>
          <Card className="hidden overflow-hidden lg:block">
            <table className="w-full table-fixed text-left text-[13px]">
              <caption className="sr-only">Audit log</caption>
              <thead className="border-b border-line bg-sunken/60 text-xs text-ink-muted">
                <tr>
                  <th scope="col" className="w-44 px-5 py-3 font-medium">Time</th>
                  <th scope="col" className="w-32 px-3 py-3 font-medium">Actor</th>
                  <th scope="col" className="w-56 px-3 py-3 font-medium">Action</th>
                  <th scope="col" className="w-36 px-3 py-3 font-medium">Object</th>
                  <th scope="col" className="px-3 py-3 font-medium">Details</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-line align-top">
                {rows.map((e) => (
                  <tr key={e.id}>
                    <td className="px-5 py-3 text-ink-dim"><Time iso={e.at} /></td>
                    <td className="truncate px-3 py-3 text-ink">{e.actor}</td>
                    <td className="px-3 py-3 text-ink">{auditLabel(e.action)}</td>
                    <td className="truncate px-3 py-3 font-mono text-xs text-ink-dim">{objectText(e)}</td>
                    <td className="px-3 py-3"><Details details={e.details} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Card>
          <div className="grid gap-3 lg:hidden">
            {rows.map((e) => (
              <Card key={e.id} className="grid gap-2 p-4">
                <div className="flex items-baseline justify-between gap-3">
                  <span className="text-sm font-medium text-ink">{auditLabel(e.action)}</span>
                  <Time iso={e.at} relative className="shrink-0 text-xs text-ink-muted" />
                </div>
                <p className="text-xs text-ink-dim">
                  {e.actor} · <span className="font-mono">{objectText(e)}</span>
                </p>
                <Details details={e.details} />
              </Card>
            ))}
          </div>
          <div className="grid justify-items-center gap-2">
            {error && <p className="text-sm text-v-malicious" role="alert">{error}</p>}
            {phase === 'loading-more' ? (
              <p className="text-xs text-ink-muted">Loading…</p>
            ) : end ? (
              <p className="text-xs text-ink-muted">No more entries</p>
            ) : (
              <Button size="sm" onClick={loadMore}>Load more</Button>
            )}
          </div>
        </>
      )}
    </div>
  );
}
