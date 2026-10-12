/* One analysis: the verdict, why, the indicators, authentication, ATT&CK, the
   full report (the server's own file, sandboxed) and the downloads. Every value
   from the message is attacker-controlled: it is shown as text, indicators are
   defanged, and links are built only by attackUrl() and fileUrl(). */

import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode, type RefObject } from 'react';
import { useReducedMotion } from 'motion/react';
import { ArrowLeft, Copy, Download, FileText, Hash, MoreHorizontal, RefreshCw } from 'lucide-react';
import { AnimatedBackground } from '@/components/core/animated-background';
import { AnimatedNumber } from '@/components/core/animated-number';
import { Disclosure, DisclosureContent, DisclosureTrigger } from '@/components/core/disclosure';
import { Dock, DockIcon, DockItem, DockLabel } from '@/components/core/dock';
import { GlowEffect } from '@/components/core/glow-effect';
import { InView } from '@/components/core/in-view';
import { ScrollProgress } from '@/components/core/scroll-progress';
import { TextScramble } from '@/components/core/text-scramble';
import { TextShimmer } from '@/components/core/text-shimmer';
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '@/components/core/dialog';
import { FileDownloads } from '@/components/phishhawk/FileDownloads';
import { ReportFrame } from '@/components/phishhawk/ReportFrame';
import { deleteMessage, getAnalysis, holdMessage, reanalyze, releaseMessage } from '@/api/client';
import { waitForSubmission } from '@/api/poll';
import { ApiError, NETWORK_MESSAGE, isAbort } from '@/api/errors';
import type { Analysis, Report, Session } from '@/api/types';
import { analysisActions } from '@/app/permissions';
import { Link, navigate } from '@/app/router';
import { SEVERITY_ORDER, SOURCE_LABEL, VERDICT_GLOW, verdictTone } from '@/app/vocabulary';
import { attackUrl, defangDomain, defangUrl, showIndicator } from '@/security/safe';
import { Button, Card, Chip, ConfirmDialog, CopyButton, ErrorState, Panel, SectionTitle, SeverityBadge, Skeleton, Time, middle } from '@/components/ui/ui';
import { useToast } from '@/components/ui/toast';
import { cn } from '@/lib/utils';

const TABS = ['Overview', 'Indicators', 'Authentication', 'ATT&CK', 'Report', 'Files'] as const;
type Tab = (typeof TABS)[number];

type Confirm = 'tier1' | 'all' | null;

function copyText(text: string) {
  return navigator.clipboard ? navigator.clipboard.writeText(text) : Promise.reject(new Error('no clipboard'));
}

function Reveal({ children }: { children: ReactNode }) {
  return (
    <InView
      once
      viewOptions={{ margin: '0px 0px -8% 0px' }}
      variants={{ hidden: { opacity: 0, y: 12 }, visible: { opacity: 1, y: 0 } }}
      transition={{ duration: 0.4, ease: [0.32, 0.72, 0, 1] }}
    >
      {children}
    </InView>
  );
}

function Meta({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="grid min-w-0 gap-1">
      <dt className="text-xs text-ink-muted">{label}</dt>
      <dd className="min-w-0 text-sm text-ink">{children}</dd>
    </div>
  );
}

function TechniqueChip({ id, name }: { id: string; name?: string }) {
  const href = attackUrl(id);
  const inner = <span className="font-mono">{id}</span>;
  return href ? (
    <a href={href} target="_blank" rel="noopener noreferrer" title={name} className="inline-flex rounded-full border border-accent/30 bg-accent/10 px-2 py-0.5 text-[11px] text-accent hover:bg-accent/15">
      {inner}
    </a>
  ) : (
    <span className="inline-flex rounded-full border border-line px-2 py-0.5 text-[11px] text-ink-muted">{inner}</span>
  );
}

/** The command bar's height (it scales with the window), for the sticky tabs under it. */
function useCommandBarHeight() {
  const [height, setHeight] = useState(96);
  useEffect(() => {
    const bar = document.querySelector<HTMLElement>('.ph-commandbar');
    if (!bar) return;
    const update = () => setHeight(bar.offsetHeight);
    update();
    const observer = new ResizeObserver(update);
    observer.observe(bar);
    return () => observer.disconnect();
  }, []);
  return height;
}

/** Whether the tabs are stuck under the command bar, and whether more tabs hide past either end of the strip
    (phones). Both are read from the page on scroll and resize. */
function useTabStrip(tabs: RefObject<HTMLDivElement | null>, strip: RefObject<HTMLDivElement | null>, bar: number) {
  const [stuck, setStuck] = useState(false);
  const [more, setMore] = useState<'none' | 'left' | 'right' | 'both'>('none');
  useEffect(() => {
    let frame = 0;
    const check = () => {
      frame = 0;
      if (tabs.current) setStuck(tabs.current.getBoundingClientRect().top <= bar + 0.5);
      const s = strip.current;
      if (s) {
        const left = s.scrollLeft > 2;
        const right = s.scrollLeft + s.clientWidth < s.scrollWidth - 2;
        setMore(left && right ? 'both' : left ? 'left' : right ? 'right' : 'none');
      }
    };
    const schedule = () => {
      if (!frame) frame = requestAnimationFrame(check);
    };
    check();
    const s = strip.current;
    window.addEventListener('scroll', schedule, { passive: true });
    window.addEventListener('resize', schedule);
    s?.addEventListener('scroll', schedule, { passive: true });
    return () => {
      window.removeEventListener('scroll', schedule);
      window.removeEventListener('resize', schedule);
      s?.removeEventListener('scroll', schedule);
      cancelAnimationFrame(frame);
    };
  }, [tabs, strip, bar]);
  return { stuck, more };
}

// written out so Tailwind sees every class: the strip fades out where more tabs hide past its edge
const STRIP_FADE = {
  none: '',
  left: '[mask-image:linear-gradient(to_left,black_calc(100%_-_32px),transparent)]',
  right: '[mask-image:linear-gradient(to_right,black_calc(100%_-_32px),transparent)]',
  both: '[mask-image:linear-gradient(to_right,transparent,black_32px,black_calc(100%_-_32px),transparent)]',
};

/* ---- tabs ---- */

function Overview({ report }: { report: Report }) {
  const [done, setDone] = useState<Record<number, boolean>>({});
  const names = useMemo(() => Object.fromEntries(report.techniques.map((t) => [t.id, t.name])), [report.techniques]);
  const signals = useMemo(() => [...report.signals].sort((a, b) => (SEVERITY_ORDER[a.severity] ?? 9) - (SEVERITY_ORDER[b.severity] ?? 9)), [report.signals]);
  return (
    <div className="grid grid-cols-1 gap-6 lg:grid-cols-[minmax(0,1fr)_340px]">
      <div className="grid content-start gap-6">
        <Card className="p-6">
          <SectionTitle>Summary</SectionTitle>
          <ul className="mt-4 grid gap-2.5">
            {report.summary.map((line, i) => (
              <li key={i} className="flex gap-3 text-sm leading-relaxed text-ink-dim">
                <span className="mt-2 h-1.5 w-1.5 shrink-0 rounded-full bg-accent" aria-hidden="true" />
                {line}
              </li>
            ))}
          </ul>
        </Card>

        <Card className="p-6">
          <SectionTitle aside={`${signals.length} finding${signals.length === 1 ? '' : 's'}`}>Findings</SectionTitle>
          {signals.length === 0 ? (
            <p className="mt-4 text-sm text-ink-muted">No findings.</p>
          ) : (
            <ul className="mt-3 divide-y divide-line">
              {signals.map((signal, i) => (
                <li key={i}>
                  <Disclosure className="py-1" transition={{ type: 'spring', bounce: 0, duration: 0.3 }}>
                    <DisclosureTrigger>
                      <button type="button" className="grid w-full grid-cols-[auto_minmax(0,1fr)] items-start gap-x-3 gap-y-2 rounded-xl px-2 py-3 text-left hover:bg-hover sm:grid-cols-[auto_minmax(0,1fr)_auto]">
                        <SeverityBadge severity={signal.severity} />
                        <span className="break-words text-sm text-ink">{signal.label}</span>
                        <span className="col-span-2 flex flex-wrap gap-1.5 sm:col-span-1 sm:justify-end">
                          {signal.techniques.map((t) => (
                            <span key={t} className="font-mono text-[11px] text-ink-muted">
                              {t}
                            </span>
                          ))}
                        </span>
                      </button>
                    </DisclosureTrigger>
                    <DisclosureContent>
                      <div className="grid gap-2 px-2 pb-4 pl-[4.25rem] text-[13px] text-ink-dim">
                        {signal.techniques.length === 0 ? (
                          <p>This finding is not mapped to an ATT&amp;CK technique.</p>
                        ) : (
                          signal.techniques.map((t) => (
                            <p key={t} className="flex flex-wrap items-center gap-2">
                              <TechniqueChip id={t} name={names[t]} />
                              <span>{names[t] ?? 'Technique'}</span>
                            </p>
                          ))
                        )}
                      </div>
                    </DisclosureContent>
                  </Disclosure>
                </li>
              ))}
            </ul>
          )}
        </Card>

        <Reveal>
          <Card className="p-6">
            <SectionTitle aside="Your checklist; it is not saved">Recommended actions</SectionTitle>
            <ul className="mt-4 grid gap-2">
              {report.recommendations.map((line, i) => (
                <li key={i}>
                  <label className={cn('flex cursor-pointer gap-3 rounded-2xl border border-line px-4 py-3 text-sm transition-colors hover:bg-hover', done[i] ? 'text-ink-muted line-through' : 'text-ink-dim')}>
                    <input type="checkbox" checked={Boolean(done[i])} onChange={() => setDone((d) => ({ ...d, [i]: !d[i] }))} className="mt-0.5 h-4 w-4 shrink-0 accent-[var(--accent)]" />
                    {line}
                  </label>
                </li>
              ))}
            </ul>
          </Card>
        </Reveal>
      </div>

      <div className="grid content-start gap-6">
        <Card className="p-6">
          <SectionTitle>Analysis status</SectionTitle>
          <dl className="mt-4 grid gap-4">
            <Meta label="Status">{report.analysis_status.status}</Meta>
            <Meta label="Reputation">{report.analysis_status.reputation_detail ?? report.analysis_status.reputation}</Meta>
          </dl>
          {report.analysis_status.reasons.length > 0 && (
            <ul className="mt-4 grid gap-1.5 text-[13px] text-ink-dim">
              {report.analysis_status.reasons.map((r, i) => (
                <li key={i}>{r}</li>
              ))}
            </ul>
          )}
        </Card>
        <Reveal>
          <Card className="p-6">
            <SectionTitle>Limitations</SectionTitle>
            <ul className="mt-4 grid gap-2.5 text-[13px] leading-relaxed text-ink-dim">
              {report.limitations.map((l, i) => (
                <li key={i}>{l}</li>
              ))}
            </ul>
          </Card>
        </Reveal>
      </div>
    </div>
  );
}

function IndicatorRow({ children, copy, flagged }: { children: ReactNode; copy: string; flagged?: boolean }) {
  return (
    <li className={cn('flex flex-col gap-3 py-3.5 sm:flex-row sm:items-start sm:justify-between', flagged && 'rounded-xl')}>
      <div className="min-w-0 flex-1">{children}</div>
      <CopyButton text={copy} />
    </li>
  );
}

function Indicators({ analysis, report }: { analysis: Analysis; report: Report }) {
  const urls = [...report.urls].sort((a, b) => Number(b.flagged) - Number(a.flagged));
  const files = [...report.attachments].sort((a, b) => Number(b.flagged) - Number(a.flagged));
  return (
    <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
      <Card className="p-6">
        <SectionTitle aside={`${urls.filter((u) => u.flagged).length} flagged`}>Links ({urls.length})</SectionTitle>
        {urls.length === 0 ? (
          <p className="mt-4 text-sm text-ink-muted">No links in this message.</p>
        ) : (
          <ul className="mt-2 divide-y divide-line">
            {urls.map((u, i) => (
              <IndicatorRow key={i} copy={u.defanged} flagged={u.flagged}>
                <p className="break-all font-mono text-[13px] text-ink">{u.defanged}</p>
                <div className="mt-2 flex flex-wrap gap-1.5">
                  {u.flagged && <Chip className="border-v-malicious/30 bg-v-malicious/10 text-v-malicious">Flagged</Chip>}
                  {u.notes.map((n, j) => (
                    <Chip key={j}>{n}</Chip>
                  ))}
                </div>
              </IndicatorRow>
            ))}
          </ul>
        )}
      </Card>

      <Card className="p-6">
        <SectionTitle aside={`${files.filter((f) => f.flagged).length} flagged`}>Attachments ({files.length})</SectionTitle>
        {files.length === 0 ? (
          <p className="mt-4 text-sm text-ink-muted">No attachments.</p>
        ) : (
          <ul className="mt-2 divide-y divide-line">
            {files.map((f, i) => (
              <IndicatorRow key={i} copy={f.sha256} flagged={f.flagged}>
                <p className="break-all text-sm text-ink">{f.filename}</p>
                <p className="mt-1 text-xs text-ink-muted">
                  {f.true_type || f.content_type} · {f.size} bytes
                </p>
                <p className="mt-1 font-mono text-xs text-ink-dim" title={f.sha256}>
                  SHA-256 {middle(f.sha256, 12)}
                </p>
                {(f.flagged || f.notes.length > 0) && (
                  <div className="mt-2 flex flex-wrap gap-1.5">
                    {f.flagged && <Chip className="border-v-malicious/30 bg-v-malicious/10 text-v-malicious">Flagged</Chip>}
                    {f.notes.map((n, j) => (
                      <Chip key={j}>{n}</Chip>
                    ))}
                  </div>
                )}
              </IndicatorRow>
            ))}
          </ul>
        )}
      </Card>

      <Card className="p-6">
        <SectionTitle>Lookalike domains ({report.lookalikes.length})</SectionTitle>
        {report.lookalikes.length === 0 ? (
          <p className="mt-4 text-sm text-ink-muted">No lookalike domains.</p>
        ) : (
          <ul className="mt-2 divide-y divide-line">
            {report.lookalikes.map((l, i) => (
              <IndicatorRow key={i} copy={defangDomain(l.domain)}>
                <p className="break-all font-mono text-[13px] text-ink">{defangDomain(l.domain)}</p>
                <p className="mt-1 text-xs text-ink-muted">
                  imitates <span className="font-mono text-ink-dim">{defangDomain(l.target)}</span> · {l.method}
                </p>
              </IndicatorRow>
            ))}
          </ul>
        )}
      </Card>

      <Card className="p-6">
        <SectionTitle>Other indicators ({report.iocs.length})</SectionTitle>
        {report.iocs.length === 0 ? (
          <p className="mt-4 text-sm text-ink-muted">No other indicators.</p>
        ) : (
          <ul className="mt-2 divide-y divide-line">
            {report.iocs.map((ioc, i) => {
              const shown = showIndicator(ioc.type, ioc.value);
              return (
                <IndicatorRow key={i} copy={shown}>
                  <div className="flex flex-wrap items-center gap-2">
                    <Chip className="font-mono uppercase">{ioc.type}</Chip>
                    <span className="break-all font-mono text-[13px] text-ink">{shown}</span>
                  </div>
                  {ioc.context && <p className="mt-1 text-xs text-ink-muted">{ioc.context}</p>}
                </IndicatorRow>
              );
            })}
          </ul>
        )}
      </Card>

      <Card className="p-6 lg:col-span-2">
        <SectionTitle>Reputation lookups</SectionTitle>
        {analysis.lookups.length === 0 ? (
          <p className="mt-4 text-sm text-ink-muted">
            {analysis.offline ? 'Offline analysis: no reputation lookups were made.' : 'No reputation lookups were made.'}
          </p>
        ) : (
          <ul className="mt-2 divide-y divide-line">
            {analysis.lookups.map((l, i) => (
              <li key={i} className="grid gap-1 py-3 sm:grid-cols-[160px_100px_minmax(0,1fr)] sm:gap-4">
                <span className="text-sm text-ink">{l.provider}</span>
                <span className="text-xs text-ink-muted">{l.method}</span>
                <span className="break-all font-mono text-xs text-ink-dim">{defangUrl(l.url)}</span>
              </li>
            ))}
          </ul>
        )}
      </Card>
    </div>
  );
}

function Authentication({ report }: { report: Report }) {
  const aligned = (value: boolean | null) => (value === null ? 'Not applicable' : value ? 'Yes' : 'No');
  return (
    <Card className="p-6">
      <SectionTitle aside={report.authentication.status}>SPF, DKIM and DMARC</SectionTitle>
      <div className="mt-4 overflow-hidden rounded-2xl border border-line">
        <table className="w-full text-left text-sm">
          <caption className="sr-only">Authentication results</caption>
          <thead className="bg-sunken text-xs text-ink-muted">
            <tr>
              <th scope="col" className="px-4 py-3 font-medium">Check</th>
              <th scope="col" className="px-4 py-3 font-medium">Result</th>
              <th scope="col" className="hidden px-4 py-3 font-medium sm:table-cell">Domain</th>
              <th scope="col" className="px-4 py-3 font-medium">Aligned</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-line">
            {report.authentication.checks.map((c) => (
              <tr key={c.check}>
                <th scope="row" className="px-4 py-3 font-medium text-ink">{c.check}</th>
                <td className="px-4 py-3 font-mono text-xs uppercase text-ink-dim">{c.result}</td>
                <td className="hidden break-all px-4 py-3 font-mono text-xs text-ink-dim sm:table-cell">{c.domain ? defangDomain(c.domain) : '—'}</td>
                <td className="px-4 py-3 text-ink-dim">{aligned(c.aligned)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <ul className="mt-5 grid gap-2 text-sm leading-relaxed text-ink-dim">
        {report.authentication.explanation.map((line, i) => (
          <li key={i}>{line}</li>
        ))}
      </ul>
    </Card>
  );
}

function Attack({ report }: { report: Report }) {
  if (report.techniques.length === 0) return <Card className="p-6 text-sm text-ink-muted">No ATT&amp;CK techniques were mapped.</Card>;
  return (
    <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
      {report.techniques.map((t) => (
        <Card key={t.id} className="p-5">
          <div className="flex flex-wrap items-center gap-2">
            <TechniqueChip id={t.id} name={t.name} />
            <span className="text-sm font-medium text-ink">{t.name}</span>
          </div>
          <ul className="mt-3 grid gap-1.5 text-[13px] text-ink-dim">
            {t.evidence.map((e, i) => (
              <li key={i}>{e}</li>
            ))}
          </ul>
        </Card>
      ))}
    </div>
  );
}

/* ---- the screen ---- */

export default function AnalysisScreen({ id, session }: { id: number; session: Session }) {
  const toast = useToast();
  const reduceMotion = useReducedMotion();
  const [analysis, setAnalysis] = useState<Analysis | null>(null);
  const [loadError, setLoadError] = useState<ApiError | null>(null);
  const [tab, setTab] = useState<Tab>('Overview');
  const [confirm, setConfirm] = useState<Confirm>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [reanalyzing, setReanalyzing] = useState(false);
  const [actionsOpen, setActionsOpen] = useState(false);
  const tabsRef = useRef<HTMLDivElement>(null);
  const stripRef = useRef<HTMLDivElement>(null);
  const watch = useRef<AbortController | null>(null);
  const barHeight = useCommandBarHeight();
  const { stuck, more } = useTabStrip(tabsRef, stripRef, barHeight);

  const load = useCallback(
    (signal?: AbortSignal) =>
      getAnalysis(id, signal)
        .then((a) => {
          setAnalysis(a);
          setLoadError(null);
        })
        .catch((e) => {
          if (isAbort(e)) return;
          setLoadError(e instanceof ApiError ? e : new ApiError(0, 'network', NETWORK_MESSAGE));
        }),
    [id],
  );

  useEffect(() => {
    const controller = new AbortController();
    setAnalysis(null);
    setLoadError(null);
    load(controller.signal);
    return () => {
      controller.abort();
      watch.current?.abort();
    };
  }, [load]);

  function openTab(next: Tab) {
    setTab(next);
    tabsRef.current?.scrollIntoView({ behavior: reduceMotion ? 'auto' : 'smooth', block: 'start' });
  }

  if (loadError) {
    if (loadError.status === 404)
      return (
        <div className="mx-auto grid max-w-md justify-items-center gap-4 py-24 text-center">
          <h1 className="text-xl font-semibold text-ink">There is no analysis with this number.</h1>
          <Button onClick={() => navigate('/app/analyses')}>Back to the queue</Button>
        </div>
      );
    return <ErrorState detail={loadError.detail} onRetry={() => load()} />;
  }

  if (!analysis) {
    return (
      <div className="grid gap-6" aria-busy="true" aria-label="Loading the analysis">
        <Skeleton className="h-64 rounded-[28px]" />
        <Skeleton className="h-11 w-full max-w-xl rounded-full" />
        <Skeleton className="h-72 rounded-[20px]" />
      </div>
    );
  }

  const report = analysis.report;
  const can = analysisActions(session, analysis);
  const tone = verdictTone(analysis.verdict);
  const htmlFile = analysis.files.find((f) => f.kind === 'html' && f.available);

  async function run(action: () => Promise<unknown>, done: string) {
    setBusy(true);
    setActionError(null);
    try {
      await action();
      await load();
      toast(done);
      setConfirm(null);
      setActionsOpen(false);
    } catch (e) {
      setActionError(e instanceof ApiError ? e.detail : NETWORK_MESSAGE);
    } finally {
      setBusy(false);
    }
  }

  async function startReanalyze() {
    setActionsOpen(false);
    setActionError(null);
    watch.current?.abort();
    const controller = new AbortController();
    watch.current = controller;
    setReanalyzing(true);
    try {
      const submission = await reanalyze(analysis!.id);
      const result = await waitForSubmission(submission.id, { signal: controller.signal });
      if (result.status === 'done' && result.analysis_id) navigate(`/app/analyses/${result.analysis_id}`);
      else setActionError(result.error || 'The analysis failed.');
    } catch (e) {
      if (!isAbort(e)) setActionError(e instanceof ApiError ? e.detail : NETWORK_MESSAGE);
    } finally {
      setReanalyzing(false);
    }
  }

  const actionButtons = (
    <>
      {can.reanalyze && (
        <Button size="sm" onClick={startReanalyze} disabled={busy || reanalyzing}>
          <RefreshCw className="h-3.5 w-3.5" strokeWidth={1.75} /> Re-analyze
        </Button>
      )}
      {can.hold && (
        <Button size="sm" onClick={() => run(() => holdMessage(analysis.message_id), 'The message is on hold.')} disabled={busy}>
          Hold
        </Button>
      )}
      {can.release && (
        <Button size="sm" onClick={() => run(() => releaseMessage(analysis.message_id), 'Hold released.')} disabled={busy}>
          Release hold
        </Button>
      )}
      {can.deleteNow && (
        <Button size="sm" variant="danger" onClick={() => {
            setActionsOpen(false);
            setConfirm('tier1');
          }} disabled={busy}>
          Delete now
        </Button>
      )}
      {can.deleteCompletely && (
        <Button size="sm" variant="danger" onClick={() => {
            setActionsOpen(false);
            setConfirm('all');
          }} disabled={busy}>
          Delete completely
        </Button>
      )}
    </>
  );
  const hasActions = can.reanalyze || can.hold || can.release || can.deleteNow || can.deleteCompletely;

  const dockItems = [
    { label: 'Back to Queue', icon: <ArrowLeft className="h-full w-full" strokeWidth={1.5} />, run: () => navigate('/app/analyses') },
    { label: 'Copy report ID', icon: <Copy className="h-full w-full" strokeWidth={1.5} />, run: () => copyText(analysis.report_id).then(() => toast('Copied'), () => toast('Select the text to copy it')) },
    { label: 'Copy SHA-256', icon: <Hash className="h-full w-full" strokeWidth={1.5} />, run: () => copyText(analysis.sha256).then(() => toast('Copied'), () => toast('Select the text to copy it')) },
    ...(can.reportFrame && htmlFile ? [{ label: 'Full report', icon: <FileText className="h-full w-full" strokeWidth={1.5} />, run: () => openTab('Report') }] : []),
    ...(can.downloads ? [{ label: 'Downloads', icon: <Download className="h-full w-full" strokeWidth={1.5} />, run: () => openTab('Files') }] : []),
  ];

  return (
    <div className="grid grid-cols-1 gap-8 pb-20 lg:pb-24">
      <ScrollProgress className="fixed inset-x-0 top-0 z-50 h-0.5 bg-accent" />

      <Link href="/app/analyses" className="inline-flex w-max items-center gap-2 text-sm text-ink-muted hover:text-ink">
        <ArrowLeft className="h-4 w-4" strokeWidth={1.5} /> Queue
      </Link>

      {/* verdict hero */}
      <div className="relative">
        <GlowEffect
          className="opacity-[var(--glow-strength)]"
          colors={[VERDICT_GLOW[analysis.verdict] ?? 'var(--verdict-neutral)', 'transparent']}
          mode="static"
          blur="strong"
          scale={0.92}
        />
        <Panel className="relative">
          <div className="grid grid-cols-1 gap-8 p-6 sm:p-8 lg:grid-cols-[minmax(0,1fr)_260px]">
            <div className="min-w-0">
              <p className={cn('text-[40px] font-semibold leading-none tracking-[-0.03em] sm:text-[52px]', tone.text)}>{analysis.verdict}</p>
              <h1 className={cn('mt-5 break-words text-xl font-medium leading-snug sm:text-2xl', analysis.subject === null ? 'text-ink-muted' : 'text-ink')}>
                {analysis.subject ?? 'Message deleted'}
              </h1>
              <dl className="mt-6 grid gap-x-8 gap-y-4 sm:grid-cols-2">
                <Meta label="From">
                  <span className="break-all font-mono text-[13px]">
                    {report?.from_display ? `${report.from_display} ` : ''}
                    {showIndicator('email', report?.from_address || analysis.sender)}
                  </span>
                </Meta>
                {report?.reply_to && (
                  <Meta label="Reply-To">
                    <span className="break-all font-mono text-[13px]">{showIndicator('email', report.reply_to)}</span>
                  </Meta>
                )}
                <Meta label="Report ID">
                  <span className="flex flex-wrap items-center gap-2">
                    <span className="sr-only">{analysis.report_id}</span>
                    <span aria-hidden="true" className="font-mono text-[13px]">
                      <TextScramble speed={0.02}>{analysis.report_id}</TextScramble>
                    </span>
                    <CopyButton text={analysis.report_id} label="Copy report ID" />
                  </span>
                </Meta>
                <Meta label="SHA-256">
                  <span className="flex flex-wrap items-center gap-2">
                    <span className="font-mono text-[13px]" title={analysis.sha256}>
                      {middle(analysis.sha256, 8)}
                    </span>
                    <CopyButton text={analysis.sha256} label="Copy SHA-256" />
                  </span>
                </Meta>
                <Meta label="Submitted">
                  {analysis.submitted_by_name ? `${analysis.submitted_by_name}, ` : ''}
                  <Time iso={analysis.created_at} /> · {SOURCE_LABEL[analysis.source] ?? analysis.source}
                </Meta>
                <Meta label="Lookups">{analysis.offline ? 'Offline analysis: no reputation lookups' : analysis.providers.join(', ') || 'None'}</Meta>
              </dl>
            </div>

            <div className="grid content-start gap-4">
              <div className="rounded-[22px] border border-line bg-raised p-5 text-center">
                <p className="text-xs text-ink-muted">Risk score</p>
                <AnimatedNumber className="mt-1 block font-mono text-5xl font-semibold tabular-nums text-ink" springOptions={{ bounce: 0, duration: 900 }} value={analysis.score} />
                <p className="mt-2 text-xs leading-relaxed text-ink-muted">The sum of the findings below; it has no maximum.</p>
              </div>
              {hasActions && <div className="hidden flex-wrap gap-2 lg:flex">{actionButtons}</div>}
            </div>
          </div>

          {(analysis.hold || analysis.tier1_deleted_at || (!report && !analysis.tier1_deleted_at) || reanalyzing || actionError) && (
            <div className="grid gap-2 border-t border-line px-6 py-4 sm:px-8">
              {analysis.hold && <p className="text-sm text-v-suspicious">This message is on hold. It cannot be deleted until an admin releases it.</p>}
              {analysis.tier1_deleted_at && (
                <p className="text-sm text-ink-dim">
                  The message and its reports were deleted on <Time iso={analysis.tier1_deleted_at} />. The verdict and this record are kept.
                </p>
              )}
              {!report && !analysis.tier1_deleted_at && <p className="text-sm text-ink-dim">The full report is not available for this message.</p>}
              {reanalyzing && <TextShimmer className="text-sm" duration={1.2}>Analyzing message again</TextShimmer>}
              {actionError && !confirm && (
                <p className="text-sm text-v-malicious" role="alert">
                  {actionError}
                </p>
              )}
            </div>
          )}
        </Panel>
      </div>

      {/* tabs */}
      {/* Stuck under the command bar, the tabs get a solid band from the top of the window down, so the page
          does not show between the bar and the tabs. */}
      <div
        ref={tabsRef}
        data-stuck={stuck}
        style={{ top: barHeight, scrollMarginTop: barHeight + 8, ['--bar' as string]: `${barHeight}px` }}
        className="min-w-0 sticky z-20 -mx-4 bg-canvas/80 px-4 py-2 backdrop-blur-xl md:-mx-6 md:px-6 lg:-mx-8 lg:px-8 data-[stuck=true]:bg-transparent data-[stuck=true]:backdrop-blur-none data-[stuck=true]:before:absolute data-[stuck=true]:before:bottom-0 data-[stuck=true]:before:left-1/2 data-[stuck=true]:before:-z-10 data-[stuck=true]:before:h-[calc(100%_+_var(--bar))] data-[stuck=true]:before:w-screen data-[stuck=true]:before:-translate-x-1/2 data-[stuck=true]:before:bg-canvas data-[stuck=true]:before:shadow-[0_1px_0_var(--line)] data-[stuck=true]:before:content-[''] print:static"
      >
        <div ref={stripRef} className={cn('overflow-x-auto overscroll-x-contain [scrollbar-width:none]', STRIP_FADE[more])}>
          <div role="tablist" aria-label="Analysis sections" className="w-max rounded-full border border-line bg-surface p-1">
            <AnimatedBackground
              defaultValue={tab}
              onValueChange={(v) => {
                if (!v) return;
                setTab(v as Tab);
                // bring the chosen tab fully into the strip on phones
                const strip = stripRef.current;
                const button = strip?.querySelector<HTMLElement>(`[data-id="${v}"]`);
                if (!strip || !button) return;
                const b = button.getBoundingClientRect();
                const s = strip.getBoundingClientRect();
                const by = b.left < s.left + 32 ? b.left - s.left - 32 : b.right > s.right - 32 ? b.right - s.right + 32 : 0;
                if (by) strip.scrollBy({ left: by, behavior: reduceMotion ? 'auto' : 'smooth' });
              }}
              className="rounded-full [background:var(--pill-active-bg)]"
              transition={{ type: 'spring', bounce: 0.2, duration: 0.5 }}
            >
              {TABS.map((t) => (
                <button
                  key={t}
                  data-id={t}
                  type="button"
                  role="tab"
                  aria-selected={tab === t}
                  className={cn('h-9 shrink-0 items-center justify-center rounded-full px-4 text-sm font-medium transition-colors duration-300', tab === t ? 'text-[var(--pill-active-ink)]' : 'text-ink-dim hover:text-ink')}
                >
                  {t}
                </button>
              ))}
            </AnimatedBackground>
          </div>
        </div>
      </div>

      <section role="tabpanel" aria-label={tab} key={tab}>
        {tab === 'Overview' && (report ? <Overview report={report} /> : <Card className="p-6 text-sm text-ink-muted">The findings were deleted with the message.</Card>)}
        {tab === 'Indicators' && (report ? <Indicators analysis={analysis} report={report} /> : <Card className="p-6 text-sm text-ink-muted">The indicators were deleted with the message.</Card>)}
        {tab === 'Authentication' && (report ? <Authentication report={report} /> : <Card className="p-6 text-sm text-ink-muted">Not available: the message was deleted.</Card>)}
        {tab === 'ATT&CK' && (report ? <Attack report={report} /> : <Card className="p-6 text-sm text-ink-muted">Not available: the message was deleted.</Card>)}
        {tab === 'Report' &&
          (can.reportFrame ? (
            <Panel>
              <div className="p-3">
                <ReportFrame analysisId={analysis.id} files={analysis.files} />
              </div>
            </Panel>
          ) : (
            <Card className="p-6 text-sm text-ink-muted">The full report was deleted with the message.</Card>
          ))}
        {tab === 'Files' &&
          (can.downloads ? (
            <Card className="px-6 py-2">
              <FileDownloads analysisId={analysis.id} messageId={analysis.message_id} files={analysis.files} canDownloadRaw={can.rawMessage} />
            </Card>
          ) : (
            <Card className="p-6 text-sm text-ink-muted">The message and its reports were deleted. The verdict and this record are kept.</Card>
          ))}
      </section>

      {/* desktop: quick actions dock */}
      {!reduceMotion && (
        <div className="pointer-events-none fixed inset-x-0 bottom-5 z-30 hidden justify-center lg:flex print:hidden">
          <div
            className="pointer-events-auto"
            onKeyDown={(e) => {
              // the kit's DockItem is role="button" without keyboard handling
              const target = e.target as HTMLElement;
              if ((e.key === 'Enter' || e.key === ' ') && target.getAttribute('role') === 'button') {
                e.preventDefault();
                target.click();
              }
            }}
          >
            <Dock className="border border-line-strong bg-surface/90 backdrop-blur-xl">
              {dockItems.map((item) => (
                <DockItem key={item.label} onClick={item.run} className="aspect-square rounded-full border border-line bg-raised text-ink-dim">
                  <DockLabel className="border-line-strong bg-raised text-ink">{item.label}</DockLabel>
                  <DockIcon>{item.icon}</DockIcon>
                </DockItem>
              ))}
            </Dock>
          </div>
        </div>
      )}

      {/* phones and tablets: action bar along the bottom */}
      <div className="fixed bottom-[max(16px,env(safe-area-inset-bottom))] left-4 right-4 z-30 flex h-11 items-center justify-around gap-1 rounded-full border border-line-strong bg-raised/90 p-1 shadow-[var(--float-shadow)] backdrop-blur-xl lg:hidden print:hidden">
        {can.reportFrame && htmlFile && (
          <button type="button" onClick={() => openTab('Report')} className="inline-flex h-9 flex-1 items-center justify-center gap-1.5 rounded-full text-xs text-ink-dim hover:bg-hover hover:text-ink">
            <FileText className="h-4 w-4" strokeWidth={1.5} /> Report
          </button>
        )}
        {can.downloads && (
          <button type="button" onClick={() => openTab('Files')} className="inline-flex h-9 flex-1 items-center justify-center gap-1.5 rounded-full text-xs text-ink-dim hover:bg-hover hover:text-ink">
            <Download className="h-4 w-4" strokeWidth={1.5} /> Files
          </button>
        )}
        {hasActions && (
          <button type="button" onClick={() => setActionsOpen(true)} className="inline-flex h-9 flex-1 items-center justify-center gap-1.5 rounded-full text-xs text-ink-dim hover:bg-hover hover:text-ink">
            <MoreHorizontal className="h-4 w-4" strokeWidth={1.5} /> Actions
          </button>
        )}
      </div>

      <Dialog open={actionsOpen} onOpenChange={setActionsOpen}>
        <DialogContent className="w-[min(420px,calc(100vw-32px))] rounded-[24px] border border-line-strong bg-raised p-6 text-ink backdrop:bg-black/60">
          <DialogHeader>
            <DialogTitle className="text-lg font-semibold text-ink">Actions</DialogTitle>
          </DialogHeader>
          <div className="mt-4 grid gap-2 [&>button]:w-full">{actionButtons}</div>
          {actionError && (
            <p className="mt-3 text-sm text-v-malicious" role="alert">
              {actionError}
            </p>
          )}
          <Button size="sm" variant="ghost" className="mt-3 w-full" onClick={() => setActionsOpen(false)}>
            Close
          </Button>
        </DialogContent>
      </Dialog>

      <ConfirmDialog
        open={confirm === 'tier1'}
        onOpenChange={(open) => !open && setConfirm(null)}
        title="Delete this message now?"
        body="This removes the message and its reports. The verdict and this record are kept."
        confirmLabel="Delete now"
        danger
        busy={busy}
        error={confirm === 'tier1' ? actionError : null}
        onConfirm={() => run(() => deleteMessage(analysis.message_id, 'tier1'), 'Message deleted. The verdict and record are kept.')}
      />
      <ConfirmDialog
        open={confirm === 'all'}
        onOpenChange={(open) => !open && setConfirm(null)}
        title="Delete everything about this message?"
        body="This removes the message, its reports and this record. The audit log keeps the message's SHA-256."
        confirmLabel="Delete completely"
        danger
        busy={busy}
        error={confirm === 'all' ? actionError : null}
        onConfirm={async () => {
          setBusy(true);
          setActionError(null);
          try {
            await deleteMessage(analysis.message_id, 'all');
            toast('Deleted completely.');
            setConfirm(null);
            navigate('/app/analyses');
          } catch (e) {
            setActionError(e instanceof ApiError ? e.detail : NETWORK_MESSAGE);
          } finally {
            setBusy(false);
          }
        }}
      />
    </div>
  );
}
