/* The reputation providers and their API keys, as Settings and the setup after
   sign-up show them. A saved key is never shown: only its last four characters.
   When a provider is on, PhishHawk sends it indicators, never the email itself. */

import { PROVIDERS } from '@/app/vocabulary';
import { Button, Switch, TextField } from '@/components/ui/ui';

export function ProviderFields({
  saved,
  providers,
  onProvidersChange,
  keys,
  onKeysChange,
  onRemoveKey,
}: {
  /** the last four characters of each saved key */
  saved: Record<string, string>;
  providers: string[];
  onProvidersChange: (next: string[]) => void;
  /** the keys typed here, not saved yet */
  keys: Record<string, string>;
  onKeysChange: (next: Record<string, string>) => void;
  onRemoveKey?: (id: string) => void;
}) {
  return (
    <div className="grid gap-3">
      {PROVIDERS.map((p) => {
        const ending = saved[p.id] ?? '';
        return (
          <div key={p.id} className="grid gap-4 rounded-[20px] border border-line bg-raised p-5">
            <Switch
              checked={providers.includes(p.id)}
              onChange={(on) => onProvidersChange(on ? [...providers, p.id] : providers.filter((x) => x !== p.id))}
              label={p.name}
              description={`When this is on, PhishHawk sends indicators (never the email itself) to ${p.name}.`}
            />
            {p.needsKey && (
              <div className="flex flex-wrap items-end gap-3">
                <TextField
                  data-bwignore="true" data-1p-ignore="true" data-lpignore="true"
                  className="min-w-[220px] flex-1"
                  label="API key"
                  type="password"
                  autoComplete="off"
                  value={keys[p.id] ?? ''}
                  onChange={(e) => onKeysChange({ ...keys, [p.id]: e.target.value })}
                  placeholder={ending ? 'Type a new key to replace it' : 'Paste the key'}
                  hint={ending ? `Saved key ending ${ending.replace(/^\.+/, '')}` : 'No key saved'}
                />
                {ending && onRemoveKey && (
                  <Button size="sm" variant="ghost" className="mb-6" onClick={() => onRemoveKey(p.id)}>
                    Remove key
                  </Button>
                )}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}

/** The keys worth sending: only those typed in. */
export function typedKeys(keys: Record<string, string>): Record<string, string> {
  return Object.fromEntries(Object.entries(keys).filter(([, v]) => v.trim()));
}
