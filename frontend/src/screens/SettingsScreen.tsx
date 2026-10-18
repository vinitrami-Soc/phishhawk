/* Settings (admin): reputation providers and their keys, domain lists, limits,
   all of them the workspace's own. Keys are never shown or sent back: the server
   returns only their last four characters, and a key is sent only when the admin
   types a new one. The upload and batch limits are the whole server's: only its
   owner changes them, and the owner also decides who may create an account. */

import { useEffect, useState, type ReactNode } from 'react';
import { Plus, X } from 'lucide-react';
import { TextMorph } from '@/components/core/text-morph';
import { getServerSettings, getSettings, patchServerSettings, patchSettings } from '@/api/client';
import { ApiError, NETWORK_MESSAGE, isAbort } from '@/api/errors';
import type { ServerSettings, Session, Settings, SettingsPatch } from '@/api/types';
import { normaliseDomain, parseLimit } from '@/lib/validate';
import { ProviderFields, typedKeys } from '@/components/phishhawk/ProviderFields';
import { Button, ConfirmDialog, ErrorState, PageHeader, Panel, SectionTitle, Skeleton, Switch, TextField } from '@/components/ui/ui';

type SaveState = 'idle' | 'saving' | 'saved';

function Section({ title, description, children, onSave, state, error }: { title: string; description: string; children: ReactNode; onSave: () => void; state: SaveState; error: string | null }) {
  return (
    <Panel>
      <div className="grid grid-cols-1 gap-6 p-6 sm:p-7">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div className="min-w-0 flex-1 basis-64">
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
            <button type="button" aria-label={`Remove ${v}`} onClick={() => onChange(values.filter((x) => x !== v))} className="grid h-6 w-6 place-items-center rounded-full text-ink-muted hover:bg-hover hover:text-ink">
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

/** The limits only the server's owner changes; the others are the workspace's. */
const SERVER_LIMITS = ['max_upload_mb', 'max_batch_messages'];

/** Who may create an account (the owner only): a switch, and how many accounts a day the server takes. */
const DAILY: { key: 'daily_messages_organization' | 'daily_messages_individual'; label: string }[] = [
  { key: 'daily_messages_organization', label: 'Messages a day, each organization' },
  { key: 'daily_messages_individual', label: 'Messages a day, each person on their own' },
];

function SignupSection() {
  const [server, setServer] = useState<ServerSettings | null>(null);
  const [open, setOpen] = useState(false);
  const [cap, setCap] = useState('');
  const [daily, setDaily] = useState<Record<string, string>>({});
  const [state, setState] = useState<SaveState>('idle');
  const [error, setError] = useState<string | null>(null);

  function adopt(s: ServerSettings) {
    setServer(s);
    setOpen(s.signup_open);
    setCap(String(s.signup_daily_cap));
    setDaily(Object.fromEntries(DAILY.map(({ key }) => [key, String(s[key])])));
  }

  useEffect(() => {
    const controller = new AbortController();
    getServerSettings(controller.signal)
      .then(adopt)
      .catch((e) => !isAbort(e) && setError(e instanceof ApiError ? e.detail : NETWORK_MESSAGE));
    return () => controller.abort();
  }, []);

  async function save() {
    const accounts = parseLimit(cap);
    if (accounts === null) return setError('Accounts a day must be a whole number from 1 to 100000.');
    const messages = DAILY.map(({ key }) => [key, parseLimit(daily[key] ?? '')] as const);
    if (messages.some(([, value]) => value === null)) return setError('Messages a day must be a whole number from 1 to 100000.');
    setState('saving');
    setError(null);
    try {
      adopt(await patchServerSettings({ signup_open: open, signup_daily_cap: accounts, ...Object.fromEntries(messages) }));
      setState('saved');
      setTimeout(() => setState('idle'), 1600);
    } catch (e) {
      setError(e instanceof ApiError ? e.detail : NETWORK_MESSAGE);
      setState('idle');
    }
  }

  return (
    <Section title="Sign-up and daily messages" description="For the whole server: you own it. People who create an account get a workspace of their own and see nothing of anyone else's." state={state} error={error} onSave={save}>
      {!server && !error ? (
        <Skeleton className="h-24 rounded-2xl" />
      ) : (
        <div className="grid gap-5">
          <Switch
            checked={open}
            onChange={setOpen}
            label="Anyone can create an account"
            description="Off: accounts come only from you, your admins and their invitations. Sign-in then shows no Create account."
          />
          <TextField
            label="New accounts a day, at most"
            type="number"
            min={1}
            max={100000}
            inputMode="numeric"
            value={cap}
            onChange={(e) => setCap(e.target.value)}
            hint="For the whole server. One address can also create only 3 an hour."
            className="sm:max-w-xs"
          />
          <div className="grid gap-4 sm:grid-cols-2">
            {DAILY.map(({ key, label }) => (
              <TextField
                key={key}
                label={label}
                type="number"
                min={1}
                max={100000}
                inputMode="numeric"
                value={daily[key] ?? ''}
                onChange={(e) => setDaily((d) => ({ ...d, [key]: e.target.value }))}
                hint="Every upload, paste, batch message, new analysis and mailbox import counts. Past it, more come after 00:00 UTC."
              />
            ))}
          </div>
        </div>
      )}
    </Section>
  );
}

const LIMITS: { key: 'retention_days' | 'max_upload_mb' | 'max_batch_messages' | 'campaign_window_days'; label: string }[] = [
  { key: 'retention_days', label: 'Keep messages and reports for (days)' },
  { key: 'max_upload_mb', label: 'Largest upload (MB)' },
  { key: 'max_batch_messages', label: 'Messages per batch' },
  { key: 'campaign_window_days', label: 'Campaign window (days)' },
];

export default function SettingsScreen({ session }: { session: Session }) {
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

  const typed = typedKeys(keys);

  return (
    <div className="grid max-w-4xl grid-cols-1 gap-8">
      <PageHeader eyebrow="Settings" title="Settings" description="Reputation providers, your domains, and limits. Changes apply to new analyses." />

      <Section
        title="Reputation providers"
        description="All are off on a new install. Offline analyses never use them."
        state={state.providers ?? 'idle'}
        error={errors.providers ?? null}
        onSave={() => save('providers', { providers, ...(Object.keys(typed).length ? { keys: typed } : {}) }, () => setKeys({}))}
      >
        <ProviderFields saved={settings.keys} providers={providers} onProvidersChange={setProviders} keys={keys} onKeysChange={setKeys} onRemoveKey={setRemoveKey} />
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
        description={session.owner ? 'Each accepts 1 to 100000. The upload and batch limits apply to the whole server.' : "Each accepts 1 to 100000. The upload and batch limits are the server owner's to change."}
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
            <TextField
              key={key}
              label={label}
              type="number"
              min={1}
              max={100000}
              inputMode="numeric"
              value={limits[key] ?? ''}
              onChange={(e) => setLimits((l) => ({ ...l, [key]: e.target.value }))}
              disabled={!session.owner && SERVER_LIMITS.includes(key)}
              hint={!session.owner && SERVER_LIMITS.includes(key) ? 'Set by the server owner.' : undefined}
            />
          ))}
        </div>
      </Section>

      {session.owner && <SignupSection />}

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
