/* Campaigns: reported messages that share infrastructure (an attachment, a
   phishing domain or link, a sender, or two weaker traits together), largest
   first, as the server finds them after each analysis. */

import { useEffect, useState } from 'react';
import { ChevronRight } from 'lucide-react';
import { listCampaigns } from '@/api/client';
import { ApiError, NETWORK_MESSAGE, isAbort } from '@/api/errors';
import type { CampaignSummary } from '@/api/types';
import { Link } from '@/app/router';
import { formatDateTime } from '@/lib/format';
import { SharedTraits } from '@/components/phishhawk/SharedTraits';
import { Card, EmptyState, ErrorState, PageHeader, SkeletonRows, VerdictBadge } from '@/components/ui/ui';

export function seen(first: string, last: string) {
  if (!first) return 'Date unknown';
  return first === last ? formatDateTime(first) : `${formatDateTime(first)} to ${formatDateTime(last)}`;
}

export default function CampaignsScreen() {
  const [rows, setRows] = useState<CampaignSummary[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    const controller = new AbortController();
    setError(null);
    listCampaigns(controller.signal)
      .then(setRows)
      .catch((e) => {
        if (!isAbort(e)) setError(e instanceof ApiError ? e.detail : NETWORK_MESSAGE);
      });
    return () => controller.abort();
  }, [attempt]);

  return (
    <div className="grid grid-cols-1 gap-8">
      <PageHeader
        eyebrow="Campaigns"
        title="Campaigns"
        description="Reported messages that share an attachment, a phishing domain or link, a sender, or two weaker traits together. Updated after each analysis."
      />
      {error ? (
        <ErrorState detail={error} onRetry={() => setAttempt((a) => a + 1)} />
      ) : rows === null ? (
        <SkeletonRows rows={4} />
      ) : rows.length === 0 ? (
        <EmptyState title="No campaigns yet: no two messages share enough." />
      ) : (
        <div className="grid grid-cols-1 gap-4">
          {rows.map((c) => (
            <Link key={c.id} href={`/app/campaigns/${c.id}`} className="block rounded-[24px] transition-transform duration-200 hover:-translate-y-0.5">
              <Card className="grid gap-4 p-5 sm:p-6">
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <div className="min-w-0">
                    <p className="text-base font-semibold tracking-tight text-ink">Campaign {c.id}</p>
                    <p className="text-xs text-ink-muted">
                      {c.size} messages · {seen(c.first_seen, c.last_seen)}
                    </p>
                  </div>
                  <span className="flex items-center gap-2">
                    <VerdictBadge verdict={c.worst_verdict} />
                    <ChevronRight className="h-4 w-4 text-ink-muted" strokeWidth={1.5} />
                  </span>
                </div>
                <SharedTraits traits={c.shared} limit={3} />
              </Card>
            </Link>
          ))}
        </div>
      )}
    </div>
  );
}
