/* Downloads: plain same-origin links to the server's files. Nothing is
   generated in the browser, nothing downloads until a click, and the URL is
   built only from the analysis id and the server-generated files[].name. */

import { fileUrl, rawMessageUrl } from '@/api/client';
import type { AnalysisFile } from '@/api/types';

function size(bytes: number) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}

export function FileDownloads({
  analysisId,
  messageId,
  files,
  canDownloadRaw,
}: {
  analysisId: number;
  messageId: number;
  files: AnalysisFile[];
  /** the owner of the submission, or an admin; the server checks again */
  canDownloadRaw: boolean;
}) {
  return (
    <ul className="divide-y divide-[var(--line)]">
      {files.map((file) => (
        <li key={file.name} className="flex flex-wrap items-center justify-between gap-3 py-3">
          <div className="min-w-0">
            <p className="text-sm text-[var(--text)]">{file.type}</p>
            <p className="truncate font-mono text-xs text-[var(--text-muted)]">
              {size(file.size)} · {file.sha256.slice(0, 12)}…
            </p>
          </div>
          {file.available ? (
            <a className="rounded-full border border-[var(--line-strong)] px-4 py-2 text-sm" href={fileUrl(analysisId, file.name, true)} download>
              Download
            </a>
          ) : (
            <span className="text-sm text-[var(--text-muted)]">No longer available</span>
          )}
        </li>
      ))}
      {canDownloadRaw && (
        <li className="flex items-center justify-between gap-3 py-3">
          <p className="text-sm text-[var(--text)]">Raw message (.eml)</p>
          <a className="rounded-full border border-[var(--line-strong)] px-4 py-2 text-sm" href={rawMessageUrl(messageId)} download>
            Download
          </a>
        </li>
      )}
    </ul>
  );
}
