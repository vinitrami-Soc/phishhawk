/* One question that opens in place, for Help and the product page's questions. */

import type { ReactNode } from 'react';
import { ChevronDown } from 'lucide-react';

export function Question({ question, children }: { question: string; children: ReactNode }) {
  return (
    <details className="group border-b border-line last:border-b-0">
      <summary className="flex cursor-pointer list-none items-center justify-between gap-4 px-5 py-4 text-[15px] font-medium text-ink transition-colors hover:bg-hover sm:px-6 [&::-webkit-details-marker]:hidden">
        {question}
        <ChevronDown aria-hidden="true" className="h-4 w-4 shrink-0 text-ink-muted transition-transform duration-200 group-open:rotate-180 motion-reduce:transition-none" strokeWidth={1.75} />
      </summary>
      <div className="grid gap-3 px-5 pb-5 text-sm leading-relaxed text-ink-dim sm:px-6">{children}</div>
    </details>
  );
}
