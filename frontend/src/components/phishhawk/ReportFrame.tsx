/* The full HTML report, exactly as the frontend build brief requires: the
   server's own file, in an iframe with this sandbox and nothing more. The page
   never reads, writes or injects into the frame, and never builds the report
   itself. The server sends that file with its own sandboxing CSP. */

import { fileUrl } from '@/api/client';
import type { AnalysisFile } from '@/api/types';

export function ReportFrame({ analysisId, files }: { analysisId: number; files: AnalysisFile[] }) {
  const html = files.find((file) => file.kind === 'html' && file.available);
  if (!html) {
    return <p className="text-sm text-[var(--text-dim)]">The full report is not available for this message.</p>;
  }
  const src = fileUrl(analysisId, html.name);
  return (
    <div className="grid gap-3">
      <div className="h-[80vh] overflow-hidden rounded-[20px] border border-[var(--line)] bg-white">
        <iframe
          sandbox="allow-popups allow-popups-to-escape-sandbox allow-downloads"
          src={src}
          title="Full report"
          loading="lazy"
          className="h-full w-full border-0"
        />
      </div>
      <a className="inline-flex min-h-8 w-max items-center text-sm text-[var(--accent)] underline-offset-4 hover:underline" href={src} target="_blank" rel="noopener noreferrer">
        Open the report in a new tab
      </a>
    </div>
  );
}
