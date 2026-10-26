/* The analysis page for someone checking their own mail (docs/superpowers/specs/
   2026-10-26-simple-view-design.md, section 3): the verdict, which email, why,
   and what to do, in plain words. Values from the message are shown as text. */

import type { Analysis } from '@/api/types';
import { plainReasons, plainSteps, plainVerdict } from '@/app/plain';
import { VERDICT_GLOW, verdictTone } from '@/app/vocabulary';
import { GlowEffect } from '@/components/core/glow-effect';
import { Card, Panel, SectionTitle, Time } from '@/components/ui/ui';
import { cn } from '@/lib/utils';
import { showIndicator } from '@/security/safe';

export function SimpleAnalysis({ analysis }: { analysis: Analysis }) {
  const report = analysis.report;
  const verdict = plainVerdict(analysis.verdict);
  const tone = verdictTone(analysis.verdict);
  const steps = plainSteps(analysis.verdict);
  return (
    <div className="grid grid-cols-1 gap-6">
      <div className="relative">
        <GlowEffect
          className="opacity-[var(--glow-strength)]"
          colors={[VERDICT_GLOW[analysis.verdict] ?? 'var(--verdict-neutral)', 'transparent']}
          mode="static"
          blur="strong"
          scale={0.92}
        />
        <Panel className="relative">
          <div className="grid gap-6 p-6 sm:p-8">
            <div>
              <h1 className={cn('text-[28px] font-semibold leading-tight tracking-[-0.02em] sm:text-4xl', tone.text)}>{verdict.headline}</h1>
              <p className="mt-3 max-w-[60ch] text-base leading-relaxed text-ink-dim">{verdict.detail}</p>
            </div>
            <dl className="grid gap-x-8 gap-y-4 border-t border-line pt-5 sm:grid-cols-3">
              <div className="min-w-0">
                <dt className="text-xs text-ink-muted">Subject</dt>
                <dd className={cn('mt-1 break-words text-sm', analysis.subject === null ? 'text-ink-muted' : 'text-ink')}>{analysis.subject ?? 'Message deleted'}</dd>
              </div>
              <div className="min-w-0">
                <dt className="text-xs text-ink-muted">From</dt>
                <dd className="mt-1 break-all text-sm text-ink">{showIndicator('email', report?.from_address || analysis.sender)}</dd>
              </div>
              <div className="min-w-0">
                <dt className="text-xs text-ink-muted">Checked</dt>
                <dd className="mt-1 text-sm text-ink">
                  <Time iso={analysis.created_at} />
                </dd>
              </div>
            </dl>
          </div>
        </Panel>
      </div>

      {analysis.verdict !== 'NO STRONG INDICATORS' && (
        <Card className="p-6">
          <SectionTitle>Why we think so</SectionTitle>
          {report ? (
            <ul className="mt-4 grid gap-2.5">
              {plainReasons(analysis.verdict, report.signals).map((reason) => (
                <li key={reason} className="flex gap-3 text-sm leading-relaxed text-ink-dim">
                  <span className="mt-2 h-1.5 w-1.5 shrink-0 rounded-full bg-accent" aria-hidden="true" />
                  {reason}
                </li>
              ))}
            </ul>
          ) : (
            <p className="mt-4 text-sm text-ink-muted">The details were deleted with the message.</p>
          )}
        </Card>
      )}

      <Card className="p-6">
        <SectionTitle>What to do now</SectionTitle>
        <ol className="mt-4 grid gap-3">
          {steps.map((step, i) => (
            <li key={step.text} className="flex gap-3 text-sm leading-relaxed text-ink-dim">
              <span aria-hidden="true" className="grid h-6 w-6 shrink-0 place-items-center rounded-full border border-line text-xs text-ink-muted">
                {i + 1}
              </span>
              <span>
                {step.lead && <strong className="font-medium text-ink">{step.lead} </strong>}
                {step.text}
              </span>
            </li>
          ))}
        </ol>
      </Card>
    </div>
  );
}
