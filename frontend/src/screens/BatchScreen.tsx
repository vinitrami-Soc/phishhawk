/* A batch: several messages uploaded together (several files, an .mbox or a
   .zip). Each message's progress and verdict in upload order, and the combined
   reports once the last one is done. The page asks again every 2 seconds until
   then. Links are built only from the batch id and the server's files[].name. */

import { useEffect, useState } from 'react';
import { ChevronRight } from 'lucide-react';
import { TextShimmer } from '@/components/core/text-shimmer';
import { SlidingNumber } from '@/components/core/sliding-number';
import { batchFileUrl, getBatch } from '@/api/client';
import { ApiError, NETWORK_MESSAGE, isAbort } from '@/api/errors';
import type { Batch, BatchMessage } from '@/api/types';
import { Link } from '@/app/router';
import { VERDICTS } from '@/app/vocabulary';
import { formatBytes } from '@/lib/format';
import { showIndicator } from '@/security/safe';
import { Card, Chip, ErrorState, PageHeader, SectionTitle, Skeleton, SkeletonRows, Time, VerdictBadge } from '@/components/ui/ui';
import { NotFoundState } from '@/screens/StateScreens';

const STATUS_WORDS: Record<string, string> = { queued: 'Waiting', running: 'Analyzing', done: 'Done', failed: 'Failed' };

function MessageRow({ row }: { row: BatchMessage }) {
  const body = (
    <div className="grid grid-cols-[40px_minmax(0,1fr)_auto] items-center gap-4 px-5 py-3.5">
      <span className="font-mono text-xs tabular-nums text-ink-muted">#{row.position}</span>
      <div className="min-w-0">
        {row.verdict ? (
          <VerdictBadge verdict={row.verdict} />
        ) : row.status === 'failed' ? (
          <p className="text-sm text-v-malicious">Failed: {row.error || 'the message could not be analysed'}</p>
        ) : row.status === 'running' ? (
          <TextShimmer duration={1.2} className="text-sm">Analyzing</TextShimmer>
        ) : (
          <p className="text-sm text-ink-muted">{STATUS_WORDS[row.status] ?? row.status}</p>
        )}
        {row.sender && <p className="mt-1 truncate font-mono text-xs text-ink-muted">{showIndicator('email', row.sender)}</p>}
      </div>
      <span className="flex items-center gap-2">
        {row.score !== null && <span className="font-mono text-sm tabular-nums text-ink">{row.score}</span>}
        {row.analysis_id && <ChevronRight className="h-4 w-4 text-ink-muted" strokeWidth={1.5} />}
      </span>
    </div>
  );
  return row.analysis_id ? (
    <Link href={`/app/analyses/${row.analysis_id}`} className="block transition-colors hover:bg-hover">
      {body}
    </Link>
  ) : (
    body
  );
}

function CombinedReports({ batch }: { batch: Batch }) {
  if (batch.files_deleted_at) {
    return (
      <Card className="p-6 text-sm text-ink-muted">
        The combined reports were deleted <Time iso={batch.files_deleted_at} relative />, after the retention period or with a message in them. Each message keeps its own page.
      </Card>
    );
  }
  return (
    <Card className="px-6 py-2">
      <ul className="divide-y divide-line">
        {batch.files.map((file) => (
          <li key={file.name} className="flex flex-wrap items-center justify-between gap-3 py-3">
            <div className="min-w-0">
              <p className="text-sm text-ink">{file.type}</p>
              <p className="truncate font-mono text-xs text-ink-muted">
                {formatBytes(file.size)} · {file.sha256.slice(0, 12)}…
              </p>
            </div>
            <span className="flex gap-2">
              {file.kind === 'html' && (
                <a className="rounded-full border border-line-strong px-4 py-2 text-sm text-ink hover:bg-hover" href={batchFileUrl(batch.id, file.name)} target="_blank" rel="noopener noreferrer">
                  Open
                </a>
              )}
              <a className="rounded-full border border-line-strong px-4 py-2 text-sm text-ink hover:bg-hover" href={batchFileUrl(batch.id, file.name, true)} download>
                Download
              </a>
            </span>
          </li>
        ))}
      </ul>
    </Card>
  );
}

export default function BatchScreen({ id }: { id: number }) {
  const [batch, setBatch] = useState<Batch | null>(null);
  const [error, setError] = useState<ApiError | null>(null);
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    setError(null);
    const load = () =>
      getBatch(id, controller.signal)
        .then((next) => {
          setBatch(next);
          if (next.status === 'running' || next.status === 'finalizing') timer = setTimeout(load, 2000);
        })
        .catch((e) => {
          if (!isAbort(e)) setError(e instanceof ApiError ? e : new ApiError(0, 'network', NETWORK_MESSAGE));
        });
    load();
    return () => {
      controller.abort();
      clearTimeout(timer);
    };
  }, [id, attempt]);

  if (error?.status === 404) return <NotFoundState />;
  if (error && !batch) return <ErrorState detail={error.detail} onRetry={() => setAttempt((a) => a + 1)} />;
  if (!batch) {
    return (
      <div className="grid grid-cols-1 gap-8" aria-busy="true" aria-label="Loading">
        <Skeleton className="h-10 w-64" />
        <SkeletonRows rows={6} />
      </div>
    );
  }

  const finished = batch.counts.done + batch.counts.failed;
  const share = batch.total ? Math.round((finished / batch.total) * 100) : 0;
  const working = batch.status === 'running' || batch.status === 'finalizing';

  return (
    <div className="grid grid-cols-1 gap-8">
      <PageHeader
        eyebrow="Batch"
        title={`Batch ${batch.id}`}
        description={
          <>
            {batch.total} messages, uploaded <Time iso={batch.created_at} relative />
            {batch.submitted_by_name ? ` by ${batch.submitted_by_name}` : ''}
            {batch.offline ? ', analysed offline' : ''}.
          </>
        }
      />

      <Card className="grid gap-4 p-5 sm:p-6">
        <div className="flex flex-wrap items-baseline justify-between gap-3">
          <p className="text-sm text-ink" aria-live="polite">
            {batch.status === 'done' ? (
              'Every message is done.'
            ) : batch.status === 'failed' ? (
              <span className="text-v-malicious">{batch.error || 'The combined reports could not be made.'}</span>
            ) : batch.status === 'finalizing' ? (
              <TextShimmer duration={1.2}>Making the combined reports</TextShimmer>
            ) : (
              <TextShimmer duration={1.2}>Analyzing the messages</TextShimmer>
            )}
          </p>
          <span className="inline-flex items-center gap-1 font-mono text-sm tabular-nums text-ink-dim">
            <SlidingNumber value={finished} /> / {batch.total}
          </span>
        </div>
        <div className="h-2 overflow-hidden rounded-full bg-sunken" role="progressbar" aria-label="Messages done" aria-valuemin={0} aria-valuemax={batch.total} aria-valuenow={finished}>
          <div className="h-full rounded-full bg-accent transition-[width] duration-500" style={{ width: `${share}%` }} />
        </div>
        <div className="flex flex-wrap gap-2">
          {VERDICTS.filter((v) => batch.verdicts[v]).map((v) => (
            <span key={v} className="inline-flex items-center gap-2">
              <VerdictBadge verdict={v} />
              <span className="font-mono text-xs tabular-nums text-ink-dim">{batch.verdicts[v]}</span>
            </span>
          ))}
          {batch.counts.failed > 0 && <Chip>{batch.counts.failed} failed</Chip>}
        </div>
      </Card>

      {(batch.files.length > 0 || batch.files_deleted_at) && (
        <section className="grid gap-4">
          <SectionTitle>Combined reports</SectionTitle>
          <CombinedReports batch={batch} />
        </section>
      )}

      <section className="grid gap-4">
        <SectionTitle aside={working ? <span className="text-xs text-ink-muted">Updates every 2 seconds</span> : undefined}>Messages</SectionTitle>
        <Card className="divide-y divide-line overflow-hidden">
          {batch.messages.map((row) => (
            <MessageRow key={row.submission_id} row={row} />
          ))}
        </Card>
      </section>
    </div>
  );
}
