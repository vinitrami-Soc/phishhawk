/* Waiting for a verdict: GET /api/v1/submissions/{id} about every 1.5 s until
   the submission is done or failed, the caller aborts, or five minutes pass.
   One loop per submission: the caller owns the AbortController and aborts it
   when the user leaves the screen. */

import { getSubmission } from './client';
import { ApiError, TIMEOUT_MESSAGE } from './errors';
import type { Submission } from './types';

export async function waitForSubmission(
  id: number,
  options: { signal: AbortSignal; onUpdate?: (submission: Submission) => void; intervalMs?: number; timeoutMs?: number },
): Promise<Submission> {
  const { signal, onUpdate, intervalMs = 1500, timeoutMs = 5 * 60 * 1000 } = options;
  const started = Date.now();
  for (;;) {
    const submission = await getSubmission(id, signal);
    onUpdate?.(submission);
    if (submission.status === 'done' || submission.status === 'failed') return submission;
    if (Date.now() - started > timeoutMs) throw new ApiError(0, 'timeout', TIMEOUT_MESSAGE);
    await sleep(intervalMs, signal);
  }
}

function sleep(ms: number, signal: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal.aborted) return reject(new DOMException('Aborted', 'AbortError'));
    const timer = setTimeout(() => {
      signal.removeEventListener('abort', onAbort);
      resolve();
    }, ms);
    const onAbort = () => {
      clearTimeout(timer);
      reject(new DOMException('Aborted', 'AbortError'));
    };
    signal.addEventListener('abort', onAbort, { once: true });
  });
}
