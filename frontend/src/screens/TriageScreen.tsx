/* Triage: upload or paste a reported message, wait for the verdict, and see the
   latest analyses. Several files, an .mbox or a .zip are a batch: its page
   follows them. */

import { useEffect, useRef, useState } from 'react';
import { FileUp, X } from 'lucide-react';
import { AnimatedBackground } from '@/components/core/animated-background';
import { TransitionPanel } from '@/components/core/transition-panel';
import { BorderTrail } from '@/components/core/border-trail';
import { TextShimmer } from '@/components/core/text-shimmer';
import { SlidingNumber } from '@/components/core/sliding-number';
import { LiquidMetalButton } from '@/components/threeui/liquid-metal/LiquidMetalButton';
import { GetTheEmail } from '@/components/phishhawk/GetTheEmail';
import { TechnicalSwitch, useTechnicalView } from '@/components/phishhawk/TechnicalSwitch';
import { isBatch, listAnalyses, submit } from '@/api/client';
import { waitForSubmission } from '@/api/poll';
import { ApiError, NETWORK_MESSAGE, isAbort } from '@/api/errors';
import type { AnalysisSummary, Session } from '@/api/types';
import { Link, navigate } from '@/app/router';
import { showIndicator } from '@/security/safe';
import { formatBytes } from '@/lib/format';
import { Button, Card, ErrorState, PageHeader, Panel, SectionTitle, Skeleton, Switch, Time, VerdictBadge } from '@/components/ui/ui';
import { cn } from '@/lib/utils';

type Phase =
  | { kind: 'idle' }
  | { kind: 'uploading' }
  | { kind: 'analyzing'; startedAt: number }
  | { kind: 'failed'; detail: string };

function Elapsed({ since }: { since: number }) {
  const [now, setNow] = useState(Date.now());
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, []);
  return <SlidingNumber value={Math.max(0, Math.floor((now - since) / 1000))} />;
}

function RecentAnalyses({ simple }: { simple: boolean }) {
  const [rows, setRows] = useState<AnalysisSummary[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    const controller = new AbortController();
    setError(null);
    listAnalyses({}, controller.signal)
      .then((list) => setRows(list.slice(0, 10)))
      .catch((e) => {
        if (!isAbort(e)) setError(e instanceof ApiError ? e.detail : NETWORK_MESSAGE);
      });
    return () => controller.abort();
  }, [attempt]);

  return (
    <section className="grid gap-4">
      <SectionTitle aside={<Link href="/app/analyses" className="inline-flex min-h-6 items-center text-accent hover:underline">{simple ? 'See all' : 'Open the queue'}</Link>}>
        {simple ? 'Your recent checks' : 'Recent analyses'}
      </SectionTitle>
      {error ? (
        <ErrorState detail={error} onRetry={() => setAttempt((a) => a + 1)} />
      ) : rows === null ? (
        <div className="grid gap-2">
          {[0, 1, 2].map((i) => (
            <Skeleton key={i} className="h-16 rounded-2xl" />
          ))}
        </div>
      ) : rows.length === 0 ? (
        <Card className="px-6 py-10 text-center text-sm text-ink-dim">No analyses yet. Analyze a message above.</Card>
      ) : (
        <Card className="divide-y divide-line overflow-hidden">
          {rows.map((row) => {
            const subject = (
              <p className={cn('text-sm', row.subject === null ? 'text-ink-muted' : 'text-ink')}>{row.subject ?? 'Message deleted'}</p>
            );
            return (
              <Link key={row.id} href={`/app/analyses/${row.id}`} className="block px-5 py-4 transition-colors hover:bg-hover">
                {/* phones: three lines */}
                <div className="grid gap-1.5 md:hidden">
                  <div className="flex flex-wrap items-center justify-between gap-x-3 gap-y-1.5">
                    <VerdictBadge verdict={row.verdict} />
                    <span className="flex items-center gap-3 text-xs text-ink-muted">
                      <span className="font-mono text-sm tabular-nums text-ink">{row.score}</span>
                      <Time iso={row.created_at} relative />
                    </span>
                  </div>
                  <div className="line-clamp-2">{subject}</div>
                  <p className="truncate font-mono text-xs text-ink-muted">{showIndicator('email', row.sender)}</p>
                </div>
                {/* desktop: one row */}
                <div className="hidden grid-cols-[200px_minmax(0,1fr)_48px_112px] items-center gap-5 md:grid">
                  <VerdictBadge verdict={row.verdict} className="justify-self-start" />
                  <div className="min-w-0">
                    <div className="min-w-0 [&>p]:truncate">{subject}</div>
                    <p className="truncate font-mono text-xs text-ink-muted">{showIndicator('email', row.sender)}</p>
                  </div>
                  <span className="text-right font-mono text-sm tabular-nums text-ink">{row.score}</span>
                  <Time iso={row.created_at} relative className="text-right text-xs text-ink-muted" />
                </div>
              </Link>
            );
          })}
        </Card>
      )}
    </section>
  );
}

export default function TriageScreen({ session }: { session: Session }) {
  const view = useTechnicalView(session);
  const simple = !view.technical;
  const [mode, setMode] = useState<'upload' | 'paste'>('upload');
  const [files, setFiles] = useState<File[]>([]);
  const [raw, setRaw] = useState('');
  const [offline, setOffline] = useState(false);
  const [dragging, setDragging] = useState(false);
  const [pasteFocus, setPasteFocus] = useState(false);
  const [phase, setPhase] = useState<Phase>({ kind: 'idle' });
  const watch = useRef<AbortController | null>(null);
  const fileInput = useRef<HTMLInputElement>(null);

  useEffect(() => () => watch.current?.abort(), []);

  const ready = mode === 'upload' ? files.length > 0 : raw.trim().length > 0;
  const busy = phase.kind === 'uploading' || phase.kind === 'analyzing';

  async function analyze() {
    if (!ready || busy) return;
    watch.current?.abort();
    const controller = new AbortController();
    watch.current = controller;
    setPhase({ kind: 'uploading' });
    try {
      const created = await submit(mode === 'upload' ? { files, offline } : { raw, offline }, controller.signal);
      if (isBatch(created)) {
        navigate(`/app/batches/${created.batch_id}`);
        return;
      }
      const submission = created;
      setPhase({ kind: 'analyzing', startedAt: Date.now() });
      const result = await waitForSubmission(submission.id, { signal: controller.signal });
      if (result.status === 'done' && result.analysis_id) navigate(`/app/analyses/${result.analysis_id}`);
      else setPhase({ kind: 'failed', detail: result.error || 'The analysis failed.' });
    } catch (e) {
      if (isAbort(e)) return;
      setPhase({ kind: 'failed', detail: e instanceof ApiError ? e.detail : NETWORK_MESSAGE });
    }
  }

  function pick(list: FileList | null) {
    const chosen = Array.from(list ?? []);
    if (chosen.length) {
      setFiles(chosen);
      setPhase({ kind: 'idle' });
    }
  }

  const totalSize = files.reduce((sum, f) => sum + f.size, 0);
  const batchLike = files.length > 1 || files.some((f) => /\.(mbox|zip)$/i.test(f.name));

  return (
    <div className="grid grid-cols-1 gap-10">
      <PageHeader
        eyebrow={simple ? 'PhishHawk' : 'Triage'}
        title={simple ? 'Check an email' : 'Analyze a reported message'}
        description={
          simple
            ? 'Save the email from your email app and drop it here, or copy and paste it.'
            : 'Upload one or more .eml or .msg files, an .mbox or a .zip, or paste the full message with its headers.'
        }
      />
      <TechnicalSwitch view={view} />

      <Panel>
        {/* grid-cols-1: the column may shrink below a long file name, which is cut with … instead */}
        <div className="grid grid-cols-1 gap-6 p-5 sm:p-7">
          <div className="w-max rounded-full border border-line bg-sunken p-1">
            <AnimatedBackground
              defaultValue="upload"
              onValueChange={(id) => id && setMode(id as 'upload' | 'paste')}
              className="rounded-full [background:var(--pill-active-bg)]"
              transition={{ type: 'spring', bounce: 0.2, duration: 0.5 }}
            >
              {(['upload', 'paste'] as const).map((id) => (
                <button
                  key={id}
                  data-id={id}
                  type="button"
                  aria-pressed={mode === id}
                  className={cn('h-9 items-center justify-center rounded-full px-4 text-sm font-medium transition-colors duration-300', mode === id ? 'text-[var(--pill-active-ink)]' : 'text-ink-dim hover:text-ink')}
                >
                  {/* the shorter words keep the switch inside the card on the narrowest phones */}
                  <span className="min-[350px]:hidden">{id === 'upload' ? 'Upload' : 'Paste'}</span>
                  <span className="hidden min-[350px]:inline">{id === 'upload' ? 'Upload files' : 'Paste the message'}</span>
                </button>
              ))}
            </AnimatedBackground>
          </div>

          <TransitionPanel
            activeIndex={mode === 'upload' ? 0 : 1}
            transition={{ duration: 0.24, ease: [0.32, 0.72, 0, 1] }}
            variants={{ enter: { opacity: 0, y: 8 }, center: { opacity: 1, y: 0 }, exit: { opacity: 0, y: -8 } }}
          >
            <div>
              {files.length ? (
                <div className="flex items-center justify-between gap-4 rounded-[20px] border border-line bg-raised px-5 py-4">
                  <div className="flex min-w-0 items-center gap-3">
                    <span className="grid h-10 w-10 shrink-0 place-items-center rounded-xl border border-line bg-surface text-accent">
                      <FileUp className="h-[18px] w-[18px]" strokeWidth={1.5} />
                    </span>
                    <div className="min-w-0">
                      <p className="truncate text-sm text-ink">{files.length === 1 ? files[0].name : `${files.length} files`}</p>
                      <p className="truncate text-xs text-ink-muted">
                        {formatBytes(totalSize)}
                        {batchLike && ' · analysed as a batch'}
                      </p>
                    </div>
                  </div>
                  <Button size="sm" variant="ghost" onClick={() => setFiles([])} disabled={busy}>
                    <X className="h-3.5 w-3.5" strokeWidth={1.75} /> Remove
                  </Button>
                </div>
              ) : (
                <label
                  onDragOver={(e) => {
                    e.preventDefault();
                    setDragging(true);
                  }}
                  onDragLeave={() => setDragging(false)}
                  onDrop={(e) => {
                    e.preventDefault();
                    setDragging(false);
                    pick(e.dataTransfer.files);
                  }}
                  className={cn(
                    'relative grid h-[220px] cursor-pointer place-items-center overflow-hidden rounded-[20px] border border-dashed text-center transition-colors duration-300',
                    dragging ? 'border-accent bg-accent/5' : 'border-line-strong bg-raised/50 hover:bg-hover',
                  )}
                >
                  <input ref={fileInput} type="file" multiple accept=".eml,.msg,.mbox,.zip" className="sr-only" onChange={(e) => pick(e.target.files)} />
                  <span className="grid justify-items-center gap-3 px-6">
                    <span className="grid h-12 w-12 place-items-center rounded-2xl border border-line bg-surface text-ink-dim">
                      <FileUp className="h-5 w-5" strokeWidth={1.5} />
                    </span>
                    <span className="text-sm font-medium text-ink">{simple ? 'Drop the email file here, or choose it' : 'Drop .eml, .msg, .mbox or .zip files, or choose them'}</span>
                    <span className="text-xs text-ink-muted">{simple ? 'Not sure how? See How do I get the email? below.' : 'Several messages are analysed as a batch'}</span>
                  </span>
                  {dragging && <BorderTrail className="bg-linear-to-l from-cyan-200 via-cyan-400 to-cyan-200" size={120} />}
                </label>
              )}
            </div>
            <div className="relative overflow-hidden rounded-[20px] border border-line-strong bg-raised/50">
              <textarea
                aria-label="Raw message"
                rows={12}
                value={raw}
                onChange={(e) => setRaw(e.target.value)}
                onFocus={() => setPasteFocus(true)}
                onBlur={() => setPasteFocus(false)}
                placeholder={simple ? 'Paste the whole email here.' : 'Paste the full message, headers first.'}
                spellCheck={false}
                className="block w-full resize-y bg-transparent px-5 py-4 font-mono text-[13px] leading-relaxed text-ink placeholder:text-ink-muted focus:outline-none"
              />
              {pasteFocus && <BorderTrail className="bg-linear-to-l from-cyan-200 via-cyan-400 to-cyan-200" size={120} />}
            </div>
          </TransitionPanel>

          <div className="border-t border-line pt-5">
            <Switch
              checked={offline}
              onChange={setOffline}
              disabled={busy}
              label="Offline analysis"
              description="Do not send this message's indicators to reputation providers."
            />
            <p className="mt-2 min-h-5 text-[13px] text-accent" aria-live="polite">
              {offline && 'Offline analysis enabled — reputation lookups will not be performed.'}
            </p>
          </div>

          <div className="flex flex-col items-center gap-3 border-t border-line pt-6 sm:flex-row sm:justify-between">
            <div className="min-h-6 text-sm" aria-live="polite">
              {phase.kind === 'uploading' && <TextShimmer duration={1.2}>Uploading</TextShimmer>}
              {phase.kind === 'analyzing' && (
                <span className="inline-flex items-center gap-3">
                  <TextShimmer duration={1.2}>Analyzing message</TextShimmer>
                  <span className="inline-flex items-center gap-1 font-mono text-xs tabular-nums text-ink-muted">
                    <Elapsed since={phase.startedAt} /> s
                  </span>
                  <button type="button" className="text-xs text-ink-muted underline-offset-4 hover:text-ink hover:underline" onClick={() => {
                    watch.current?.abort();
                    setPhase({ kind: 'idle' });
                  }}>
                    Stop watching
                  </button>
                </span>
              )}
              {phase.kind === 'failed' && (
                <span className="text-v-malicious" role="alert">
                  {phase.detail}
                </span>
              )}
            </div>
            <LiquidMetalButton height={48} onClick={analyze} disabled={!ready || busy}>
              Analyze
            </LiquidMetalButton>
          </div>
        </div>
      </Panel>

      {simple && <GetTheEmail />}

      <RecentAnalyses simple={simple} />
    </div>
  );
}
