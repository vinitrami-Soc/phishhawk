/* A campaign's shared traits: what kind, the (defanged) value, and in how many messages. */

import type { SharedTrait } from '@/api/types';
import { sharedTrait } from '@/lib/traits';

export function SharedTraits({ traits, limit }: { traits: SharedTrait[]; limit?: number }) {
  const shown = limit ? traits.slice(0, limit) : traits;
  return (
    <ul className="grid gap-2">
      {shown.map((trait, i) => {
        const { label, value, hidden } = sharedTrait(trait);
        return (
          <li key={`${trait.kind}-${i}`} className="grid grid-cols-1 gap-0.5 sm:grid-cols-[150px_minmax(0,1fr)_auto] sm:items-baseline sm:gap-3">
            <span className="text-xs text-ink-muted">{label}</span>
            {value === null ? <span className="text-sm italic text-ink-dim">{hidden}</span> : <span className="break-all font-mono text-[13px] text-ink">{value}</span>}
            <span className="text-xs tabular-nums text-ink-muted">{trait.messages} messages</span>
          </li>
        );
      })}
      {limit && traits.length > limit && <li className="text-xs text-ink-muted">and {traits.length - limit} more</li>}
    </ul>
  );
}
