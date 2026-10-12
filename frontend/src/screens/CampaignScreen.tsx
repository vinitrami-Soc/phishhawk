/* One campaign: what links its messages, who sent and received them, and the
   messages themselves. A subject, a display name and recipient addresses are
   shown only while a message's content is kept; then "Same subject" and a count. */

import { useEffect, useState } from 'react';
import { ChevronRight } from 'lucide-react';
import { getCampaign } from '@/api/client';
import { ApiError, NETWORK_MESSAGE, isAbort } from '@/api/errors';
import type { Campaign } from '@/api/types';
import { Link } from '@/app/router';
import { showIndicator } from '@/security/safe';
import { SharedTraits } from '@/components/phishhawk/SharedTraits';
import { Card, ErrorState, PageHeader, SectionTitle, Skeleton, SkeletonRows, VerdictBadge } from '@/components/ui/ui';
import { NotFoundState } from '@/screens/StateScreens';
import { seen } from '@/screens/CampaignsScreen';
import { cn } from '@/lib/utils';

export default function CampaignScreen({ id }: { id: number }) {
  const [campaign, setCampaign] = useState<Campaign | null>(null);
  const [error, setError] = useState<ApiError | null>(null);
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    const controller = new AbortController();
    setError(null);
    setCampaign(null);
    getCampaign(id, controller.signal)
      .then(setCampaign)
      .catch((e) => {
        if (!isAbort(e)) setError(e instanceof ApiError ? e : new ApiError(0, 'network', NETWORK_MESSAGE));
      });
    return () => controller.abort();
  }, [id, attempt]);

  if (error?.status === 404) return <NotFoundState />;
  if (error) return <ErrorState detail={error.detail} onRetry={() => setAttempt((a) => a + 1)} />;
  if (!campaign) {
    return (
      <div className="grid grid-cols-1 gap-8" aria-busy="true" aria-label="Loading">
        <Skeleton className="h-10 w-64" />
        <SkeletonRows rows={4} />
      </div>
    );
  }

  return (
    <div className="grid grid-cols-1 gap-8">
      <PageHeader
        eyebrow="Campaign"
        title={`Campaign ${campaign.id}`}
        description={`${campaign.size} messages · ${seen(campaign.first_seen, campaign.last_seen)} (from their Date lines)`}
        actions={<VerdictBadge verdict={campaign.worst_verdict} />}
      />

      <section className="grid gap-4">
        <SectionTitle>What links them</SectionTitle>
        <Card className="p-5 sm:p-6">
          <SharedTraits traits={campaign.shared} />
        </Card>
      </section>

      <section className="grid gap-4">
        <SectionTitle>Senders and recipients</SectionTitle>
        <Card className="grid gap-4 p-5 text-sm sm:p-6">
          <div className="grid gap-1.5">
            <p className="text-xs text-ink-muted">Senders</p>
            {campaign.senders.length ? (
              <ul className="grid gap-1">
                {campaign.senders.map((s) => (
                  <li key={s} className="break-all font-mono text-[13px] text-ink">
                    {showIndicator('email', s)}
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-ink-dim">None recorded</p>
            )}
          </div>
          <div className="grid gap-1.5">
            <p className="text-xs text-ink-muted">Recipients</p>
            {campaign.recipients.length > 0 && (
              <ul className="grid gap-1">
                {campaign.recipients.map((r) => (
                  <li key={r} className="break-all font-mono text-[13px] text-ink">
                    {showIndicator('email', r)}
                  </li>
                ))}
              </ul>
            )}
            {!campaign.recipients_complete && (
              <p className="text-ink-dim">
                {campaign.recipient_count} recipients in all. Their addresses are shown only while a message's content is kept.
              </p>
            )}
          </div>
        </Card>
      </section>

      <section className="grid gap-4">
        <SectionTitle>Messages</SectionTitle>
        <Card className="divide-y divide-line overflow-hidden">
          {campaign.messages.map((m) => (
            <Link key={m.message_id} href={`/app/analyses/${m.analysis_id}`} className="grid grid-cols-[minmax(0,1fr)_auto] items-center gap-4 px-5 py-4 transition-colors hover:bg-hover">
              <div className="grid min-w-0 gap-1.5">
                <VerdictBadge verdict={m.verdict} className="justify-self-start" />
                <p className={cn('truncate text-sm', m.subject === null ? 'text-ink-muted' : 'text-ink')}>{m.subject ?? 'Message deleted'}</p>
                <p className="truncate font-mono text-xs text-ink-muted">{showIndicator('email', m.sender)}</p>
              </div>
              <span className="flex items-center gap-2">
                <span className="font-mono text-sm tabular-nums text-ink">{m.score}</span>
                <ChevronRight className="h-4 w-4 text-ink-muted" strokeWidth={1.5} />
              </span>
            </Link>
          ))}
        </Card>
      </section>
    </div>
  );
}
