/* Settings (admin): reputation providers and their keys, domain lists, limits.
   Keys are never shown or sent back: the server returns only their last four
   characters, and a key is sent only when the admin types a new one. */

import { useEffect, useState, type ReactNode } from 'react';
import { Plus, X } from 'lucide-react';
import { TextMorph } from '@/components/core/text-morph';
import { getSettings, patchSettings } from '@/api/client';
import { ApiError, NETWORK_MESSAGE, isAbort } from '@/api/errors';
import type { Settings, SettingsPatch } from '@/api/types';
import { PROVIDERS } from '@/app/vocabulary';
import { normaliseDomain, parseLimit } from '@/lib/validate';
import { Button, ConfirmDialog, ErrorState, PageHeader, Panel, SectionTitle, Skeleton, Switch, TextField } from '@/components/ui/ui';

type SaveState = 'idle' | 'saving' | 'saved';

function Section({ title, description, children, onSave, state, error }: { title: string; description: string; children: ReactNode; onSave: () => void; state: SaveState; error: string | null }) {
  return (
    <Panel>
      <div className="grid grid-cols-1 gap-6 p-6 sm:p-7">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <SectionTitle>{title}</SectionTitle>
            <p className="mt-1 text-[13px] text-ink-muted">{description}</p>
          </div>
          <Button size="sm" variant="primary" onClick={onSave} disabled={state === 'saving'}>
            <TextMorph>{state === 'saved' ? 'Saved' : state === 'saving' ? 'Saving' : 'Save'}</TextMorph>
          </Button>
        </div>
        {children}
        {error && (
          <p className="text-sm text-v-malicious" role="alert">
            {error}
          </p>
        )}
      </div>
    </Panel>
  );
}

function DomainList({ label, hint, values, onChange }: { label: string; hint: string; values: string[]; onChange: (next: string[]) => void }) {
  const [draft, setDraft] = useState('');
  const [error, setError] = useState<string | null>(null);
  const add = () => {
    if (!draft.trim()) return;
    const value = normaliseDomain(draft);
    if (!value) {
      setError('Enter a domain, like example.com.');
      return;
    }
    if (!values.includes(value)) onChange([...values, value]);
    setDraft('');
    setError(null);
  };
  return (
    <div className="grid grid-cols-1 gap-2">
      <p className="text-[13px] font-medium text-ink-dim">{label}</p>
      <div className="flex flex-wrap gap-1.5">
        {values.length === 0 && <span className="text-xs text-ink-muted">None</span>}
        {values.map((v) => (
          <span key={v} className="inline-flex items-center gap-1 rounded-full border border-line bg-raised py-1 pl-3 pr-1 font-mono text-xs text-ink">
            {v}
            <button type="button" aria-label={`Remove ${v}`} onClick={() => onChange(values.filter((x) => x !== v))} className="grid h-5 w-5 place-items-center rounded-full text-ink-muted hover:bg-hover hover:text-ink">
              <X className="h-3 w-3" strokeWidth={2} />
            </button>
          </span>
        ))}
      </div>
      <div className="flex gap-2">
        <input
          value={draft}
          onChange={(e) => {
            setDraft(e.target.value);
            setError(null);
          }}
          onKeyDown={(e) => {
            if (e.key === 'Enter') {
              e.preventDefault();
              add();
            }
          }}
          placeholder="example.com"
          aria-label={`Add to ${label}`}
          aria-invalid={error ? true : undefined}
          className="h-10 min-w-0 flex-1 rounded-[12px] border border-line-strong bg-raised px-3 font-mono text-sm text-ink placeholder:text-ink-muted focus:border-accent/60 focus:outline-none"
        />
        <Button size="sm" onClick={add} aria-label={`Add to ${label}`}>
          <Plus className="h-3.5 w-3.5" strokeWidth={1.75} /> Add
        </Button>
      </div>
      {error ? (
        <p className="text-xs text-v-malicious" role="alert">
          {error}
        </p>
      ) : (
        <p className="text-xs text-ink-muted">{hint}</p>
      )}
    </div>
  );
}

const LIMITS: { key: 'retention_days' | 'max_upload_mb' | 'max_batch_messages' | 'campaign_window_days'; label: string }[] = [
  { key: 'retention_days', label: 'Keep messages and reports for (days)' },
  { key: 'max_upload_mb', label: 'Largest upload (MB)' },
  { key: 'max_batch_messages', label: 'Messages per batch' },
  { key: 'campaign_window_days', label: 'Campaign window (days)' },
];

export default function SettingsScreen() {
  const [settings, setSettings] = useState<Settings | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [attempt, setAttempt] = useState(0);
  const [providers, setProviders] = useState<string[]>([]);
  const [keys, setKeys] = useState<Record<string, string>>({});
  const [domains, setDomains] = useState({ protected_domains: [] as string[], allow_domains: [] as string[], block_domains: [] as string[] });
  const [limits, setLimits] = useState<Record<string, string>>({});
  const [state, setState] = useState<Record<string, SaveState>>({});
  const [errors, setErrors] = useState<Record<string, string | null>>({});
  const [removeKey, setRemoveKey] = useState<string | null>(null);

  function adopt(s: Settings) {
    setSettings(s);
    setProviders(s.providers);
    setDomains({ protected_domains: s.protected_domains, allow_domains: s.allow_domains, block_domains: s.block_domains });
    setLimits(Object.fromEntries(LIMITS.map(({ key }) => [key, String(s[key])])));
  }

  useEffect(() => {
    const controller = new AbortController();
    setLoadError(null);
    getSettings(controller.signal)
      .then(adopt)
      .catch((e) => !isAbort(e) && setLoadError(e instanceof ApiError ? e.detail : NETWORK_MESSAGE));
    return () => controller.abort();
  }, [attempt]);

  async function save(section: string, patch: SettingsPatch, after?: () => void) {
    setState((s) => ({ ...s, [section]: 'saving' }));
    setErrors((e) => ({ ...e, [section]: null }));
    try {
      adopt(await patchSettings(patch));
      after?.();
      setState((s) => ({ ...s, [section]: 'saved' }));
      setTimeout(() => setState((s) => ({ ...s, [section]: 'idle' })), 1600);
    } catch (e) {
      setErrors((x) => ({ ...x, [section]: e instanceof ApiError ? e.detail : NETWORK_MESSAGE }));
      setState((s) => ({ ...s, [section]: 'idle' }));
    }
  }

  if (loadError) return <ErrorState detail={loadError} onRetry={() => setAttempt((a) => a + 1)} />;
  if (!settings)
    return (
      <div className="grid gap-6">
        <Skeleton className="h-16 w-72" />
        <Skeleton className="h-80 rounded-[28px]" />
      </div>
    );

  const typedKeys = Object.fromEntries(Object.entries(keys).filter(([, v]) => v.trim()));

  return (
    <div className="grid max-w-4xl grid-cols-1 gap-8">
      <PageHeader eyebrow="Settings" title="Settings" description="Reputation providers, your domains, and limits. Changes apply to new analyses." />

      <Section
        title="Reputation providers"
        description="All are off on a new install. Offline analyses never use them."
        state={state.providers ?? 'idle'}
        error={errors.providers ?? null}
        onSave={() => save('providers', { providers, ...(Object.keys(typedKeys).length ? { keys: typedKeys } : {}) }, () => setKeys({}))}
      >
        <div className="grid gap-3">
          {PROVIDERS.map((p) => {
            const saved = settings.keys[p.id] ?? '';
            return (
              <div key={p.id} className="grid gap-4 rounded-[20px] border border-line bg-raised p-5">
                <Switch
                  checked={providers.includes(p.id)}
                  onChange={(on) => setProviders((list) => (on ? [...list, p.id] : list.filter((x) => x !== p.id)))}
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
                      onChange={(e) => setKeys((k) => ({ ...k, [p.id]: e.target.value }))}
                      placeholder={saved ? 'Type a new key to replace it' : 'Paste the key'}
                      hint={saved ? `Saved key ending ${saved.replace(/^\.+/, '')}` : 'No key saved'}
                    />
                    {saved && (
                      <Button size="sm" variant="ghost" className="mb-6" onClick={() => setRemoveKey(p.id)}>
                        Remove key
                      </Button>
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </Section>

      <Section
        title="Domains"
        description="Your own domains are watched for lookalikes; allowed and blocked domains adjust verdicts."
        state={state.domains ?? 'idle'}
        error={errors.domains ?? null}
        onSave={() => save('domains', domains)}
      >
        <DomainList label="Protected domains" hint="Your organisation's domains. Lookalikes of these are flagged." values={domains.protected_domains} onChange={(v) => setDomains((d) => ({ ...d, protected_domains: v }))} />
        <DomainList label="Allowed domains" hint="Senders you trust." values={domains.allow_domains} onChange={(v) => setDomains((d) => ({ ...d, allow_domains: v }))} />
        <DomainList label="Blocked domains" hint="Senders that are always flagged." values={domains.block_domains} onChange={(v) => setDomains((d) => ({ ...d, block_domains: v }))} />
      </Section>

      <Section
        title="Limits"
        description="Each accepts 1 to 100000."
        state={state.limits ?? 'idle'}
        error={errors.limits ?? null}
        onSave={() => {
          const parsed = LIMITS.map(({ key }) => [key, parseLimit(limits[key] ?? '')] as const);
          if (parsed.some(([, value]) => value === null)) {
            setErrors((e) => ({ ...e, limits: 'Each limit must be a whole number from 1 to 100000.' }));
            return;
          }
          save('limits', Object.fromEntries(parsed) as SettingsPatch);
        }}
      >
        <div className="grid gap-4 sm:grid-cols-2">
          {LIMITS.map(({ key, label }) => (
            <TextField key={key} label={label} type="number" min={1} max={100000} inputMode="numeric" value={limits[key] ?? ''} onChange={(e) => setLimits((l) => ({ ...l, [key]: e.target.value }))} />
          ))}
        </div>
      </Section>

      <ConfirmDialog
        open={removeKey !== null}
        onOpenChange={(open) => !open && setRemoveKey(null)}
        title="Remove this API key?"
        body="Lookups with this provider stop until a new key is saved."
        confirmLabel="Remove key"
        danger
        busy={state.providers === 'saving'}
        onConfirm={() => {
          const id = removeKey!;
          save('providers', { keys: { [id]: '' } }, () => setRemoveKey(null));
        }}
      />
    </div>
  );
}
