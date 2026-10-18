/* The queue: every analysis, newest first, 50 at a time, with search and
   filters for verdict, source, who submitted, disputed and days. One state at a time:
   loading, error, empty or rows. */

import { useEffect, useRef, useState } from 'react';
import { ChevronRight, Search, X } from 'lucide-react';
import { SlidingNumber } from '@/components/core/sliding-number';
import { listAnalyses, type AnalysisQuery } from '@/api/client';
import { ApiError, NETWORK_MESSAGE, isAbort } from '@/api/errors';
import type { AnalysisSummary, Session, Verdict } from '@/api/types';
import { Link } from '@/app/router';
import { VERDICTS } from '@/app/vocabulary';
import { showIndicator } from '@/security/safe';
import { Button, Card, EmptyState, ErrorState, PageHeader, SkeletonRows, Time, VerdictBadge } from '@/components/ui/ui';
import { cn } from '@/lib/utils';

const PAGE = 50;

type State = { rows: AnalysisSummary[]; phase: 'loading' | 'ready' | 'loading-more' | 'error'; end: boolean; error?: string };

const lookups = (row: AnalysisSummary) => (row.offline ? 'Offline' : row.providers.join(', ') || 'None');

type Source = NonNullable<AnalysisQuery['source']>;
const SOURCES: { value: Source; label: string }[] = [
  { value: '', label: 'Any source' },
  { value: 'upload', label: 'Upload' },
  { value: 'paste', label: 'Paste' },
  { value: 'batch', label: 'Batch' },
  { value: 'mailbox', label: 'Mailbox' },
];

const pill = (on: boolean) =>
  cn(
    'h-9 shrink-0 rounded-full border px-3.5 text-xs font-medium transition-colors',
    on ? 'border-transparent [background:var(--pill-active-bg)] text-[var(--pill-active-ink)]' : 'border-line bg-surface text-ink-dim hover:text-ink',
  );

const dateInput = 'h-9 rounded-full border border-line-strong bg-surface px-3 text-xs text-ink focus:border-accent/60 focus:outline-none';

export default function QueueScreen({ session }: { session: Session }) {
  const [query, setQuery] = useState('');
  const [search, setSearch] = useState('');
  const [verdict, setVerdict] = useState<Verdict | ''>('');
  const [source, setSource] = useState<Source>('');
  const [mine, setMine] = useState(false);
  const [disputed, setDisputed] = useState(false);
  const [since, setSince] = useState('');
  const [until, setUntil] = useState('');
  const [state, setState] = useState<State>({ rows: [], phase: 'loading', end: false });
  const [attempt, setAttempt] = useState(0);
  const current = useRef<AbortController | null>(null);

  // debounce typing
  useEffect(() => {
    const t = setTimeout(() => setSearch(query.trim()), 300);
    return () => clearTimeout(t);
  }, [query]);

  const user = mine ? session.user_id : null;
  const filters: AnalysisQuery = { q: search, verdict, source, user, since, until, disputed };

  // first page whenever the search or a filter changes
  useEffect(() => {
    current.current?.abort();
    const controller = new AbortController();
    current.current = controller;
    setState({ rows: [], phase: 'loading', end: false });
    listAnalyses({ q: search, verdict, source, user, since, until, disputed }, controller.signal)
      .then((rows) => setState({ rows, phase: 'ready', end: rows.length < PAGE }))
      .catch((e) => {
        if (!isAbort(e)) setState({ rows: [], phase: 'error', end: false, error: e instanceof ApiError ? e.detail : NETWORK_MESSAGE });
      });
    return () => controller.abort();
  }, [search, verdict, source, user, since, until, disputed, attempt]);

  async function loadMore() {
    const controller = new AbortController();
    current.current = controller;
    setState((s) => ({ ...s, phase: 'loading-more' }));
    try {
      const more = await listAnalyses({ ...filters, offset: state.rows.length }, controller.signal);
      setState((s) => ({ rows: [...s.rows, ...more], phase: 'ready', end: more.length < PAGE }));
    } catch (e) {
      if (!isAbort(e)) setState((s) => ({ ...s, phase: 'ready', error: e instanceof ApiError ? e.detail : NETWORK_MESSAGE }));
    }
  }

  const filtered = Boolean(search || verdict || source || mine || disputed || since || until);
  const clear = () => {
    setQuery('');
    setVerdict('');
    setSource('');
    setMine(false);
    setDisputed(false);
    setSince('');
    setUntil('');
  };

  return (
    <div className="grid grid-cols-1 gap-8">
      <PageHeader
        eyebrow="Queue"
        title="Analyses"
        description="Every analysed message, newest first."
        actions={
          state.phase !== 'loading' && state.phase !== 'error' ? (
            <span className="inline-flex items-center gap-1 rounded-full border border-line bg-surface px-3 py-1.5 font-mono text-xs tabular-nums text-ink-dim">
              <SlidingNumber value={state.rows.length} /> shown
            </span>
          ) : null
        }
      />

      <div className="grid gap-3 md:grid-cols-[minmax(0,420px)_1fr] md:items-center">
        <label className="relative block">
          <span className="sr-only">Search</span>
          <Search className="pointer-events-none absolute left-4 top-1/2 h-4 w-4 -translate-y-1/2 text-ink-muted" strokeWidth={1.5} />
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={(e) => e.key === 'Escape' && setQuery('')}
            placeholder="Search a SHA-256, report ID or indicator"
            className="h-11 w-full rounded-full border border-line-strong bg-surface pl-11 pr-11 text-sm text-ink placeholder:text-ink-muted focus:border-accent/60 focus:outline-none"
          />
          {query && (
            <button type="button" aria-label="Clear search" onClick={() => setQuery('')} className="absolute right-2 top-1/2 grid h-8 w-8 -translate-y-1/2 place-items-center rounded-full text-ink-muted hover:bg-hover hover:text-ink">
              <X className="h-4 w-4" strokeWidth={1.5} />
            </button>
          )}
        </label>
        <div className="flex gap-2 overflow-x-auto [scrollbar-width:none] md:justify-end" role="group" aria-label="Filter by verdict">
          {(['', ...VERDICTS] as const).map((v) => (
            <button
              key={v || 'all'}
              type="button"
              aria-pressed={verdict === v}
              onClick={() => setVerdict(v)}
              className={pill(verdict === v)}
            >
              {v ? v.charAt(0) + v.slice(1).toLowerCase() : 'All'}
            </button>
          ))}
        </div>
      </div>

      <div className="-mt-4 flex flex-wrap items-center gap-x-4 gap-y-3">
        <div className="flex gap-2 overflow-x-auto [scrollbar-width:none]" role="group" aria-label="Filter by source">
          {SOURCES.map((s) => (
            <button key={s.value || 'any'} type="button" aria-pressed={source === s.value} onClick={() => setSource(s.value)} className={pill(source === s.value)}>
              {s.label}
            </button>
          ))}
        </div>
        {session.user_id !== null && (
          <button type="button" aria-pressed={mine} onClick={() => setMine((m) => !m)} className={pill(mine)}>
            Only mine
          </button>
        )}
        <button type="button" aria-pressed={disputed} onClick={() => setDisputed((d) => !d)} className={pill(disputed)} title="Someone said the verdict was wrong">
          Disputed
        </button>
        <div className="flex flex-wrap items-center gap-2 text-xs text-ink-muted">
          <label className="flex items-center gap-2">
            From
            <input type="date" value={since} max={until || undefined} onChange={(e) => setSince(e.target.value)} className={dateInput} />
          </label>
          <label className="flex items-center gap-2">
            To
            <input type="date" value={until} min={since || undefined} onChange={(e) => setUntil(e.target.value)} className={dateInput} />
          </label>
        </div>
      </div>

      {state.phase === 'loading' ? (
        <SkeletonRows rows={6} />
      ) : state.phase === 'error' ? (
        <ErrorState detail={state.error ?? NETWORK_MESSAGE} onRetry={() => setAttempt((a) => a + 1)} />
      ) : state.rows.length === 0 ? (
        filtered ? (
          <EmptyState
            title="No analyses match this search."
            action={
              <Button size="sm" onClick={clear}>
                Clear search
              </Button>
            }
          />
        ) : (
          <EmptyState title="No analyses yet." action={<Link href="/app/" className="text-sm text-accent hover:underline">Analyze a message</Link>} />
        )
      ) : (
        <>
          {/* desktop table */}
          <Card className="hidden overflow-hidden lg:block">
            <table className="w-full table-fixed text-left text-[13px]">
              <caption className="sr-only">Analyses</caption>
              <thead className="border-b border-line bg-sunken/60 text-xs text-ink-muted">
                <tr>
                  <th scope="col" className="w-[216px] px-5 py-3 font-medium">Verdict</th>
                  <th scope="col" className="px-3 py-3 font-medium">Subject and sender</th>
                  <th scope="col" className="w-16 px-3 py-3 text-right font-medium">Score</th>
                  <th scope="col" className="w-28 px-3 py-3 font-medium">Lookups</th>
                  <th scope="col" className="w-28 px-3 py-3 font-medium">Submitted by</th>
                  <th scope="col" className="w-32 px-3 py-3 font-medium">Analysed</th>
                  <th scope="col" className="w-10 px-3 py-3"><span className="sr-only">Open</span></th>
                </tr>
              </thead>
              <tbody className="divide-y divide-line">
                {state.rows.map((row) => (
                  <tr key={row.id} className="group relative transition-colors hover:bg-hover">
                    <td className="px-5 py-3.5"><VerdictBadge verdict={row.verdict} /></td>
                    <td className="min-w-0 px-3 py-3.5">
                      <Link href={`/app/analyses/${row.id}`} className="block min-w-0 after:absolute after:inset-0 focus-visible:outline-none">
                        <span className={cn('block truncate', row.subject === null ? 'text-ink-muted' : 'text-ink')}>{row.subject ?? 'Message deleted'}</span>
                        <span className="block truncate font-mono text-xs text-ink-muted">{showIndicator('email', row.sender)}</span>
                      </Link>
                    </td>
                    <td className="px-3 py-3.5 text-right font-mono tabular-nums text-ink">{row.score}</td>
                    <td className="truncate px-3 py-3.5 text-ink-dim">{lookups(row)}</td>
                    <td className="truncate px-3 py-3.5 text-ink-dim">{row.submitted_by_name ?? '—'}</td>
                    <td className="px-3 py-3.5 text-ink-dim"><Time iso={row.created_at} relative /></td>
                    <td className="px-3 py-3.5 text-ink-muted"><ChevronRight className="h-4 w-4 transition-transform group-hover:translate-x-0.5" strokeWidth={1.5} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Card>

          {/* phones and tablets: cards */}
          <div className="grid gap-3 lg:hidden">
            {state.rows.map((row) => (
              <Link key={row.id} href={`/app/analyses/${row.id}`} className="grid gap-2 rounded-[20px] border border-line bg-surface p-4 transition-colors hover:bg-hover">
                <div className="flex items-center justify-between gap-3">
                  <VerdictBadge verdict={row.verdict} />
                  <span className="font-mono text-sm tabular-nums text-ink">{row.score}</span>
                </div>
                <p className={cn('line-clamp-2 text-sm', row.subject === null ? 'text-ink-muted' : 'text-ink')}>{row.subject ?? 'Message deleted'}</p>
                <p className="truncate font-mono text-xs text-ink-muted">{showIndicator('email', row.sender)}</p>
                <div className="flex justify-between border-t border-line pt-2 text-xs text-ink-muted">
                  <span>Lookups: {lookups(row)}</span>
                  <Time iso={row.created_at} relative />
                </div>
              </Link>
            ))}
          </div>

          <div className="grid justify-items-center gap-2 py-2">
            {state.error && <p className="text-sm text-v-malicious" role="alert">{state.error}</p>}
            {state.phase === 'loading-more' ? (
              <div className="w-full">
                <SkeletonRows rows={1} />
              </div>
            ) : state.end ? (
              <p className="text-xs text-ink-muted">No more results</p>
            ) : (
              <Button size="sm" onClick={loadMore}>
                Load more
              </Button>
            )}
          </div>
        </>
      )}
    </div>
  );
}
