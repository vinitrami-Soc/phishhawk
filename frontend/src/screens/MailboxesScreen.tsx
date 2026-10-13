/* Report mailboxes (admin). The server reads each one, read-only, and analyses
   every new message as an upload. A credential is written once and never shown:
   the list only says one is stored. Every value here is shown as text. */

import { useEffect, useId, useState, type FormEvent } from 'react';
import { Mailbox as MailboxIcon, Pencil, Plus, RefreshCw, Trash2 } from 'lucide-react';
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from '@/components/core/dialog';
import { createMailbox, deleteMailbox, listMailboxes, pollMailbox, updateMailbox } from '@/api/client';
import { ApiError, NETWORK_MESSAGE, isAbort } from '@/api/errors';
import type { Mailbox, MailboxConfig, MailboxKind } from '@/api/types';
import { Button, Card, ConfirmDialog, EmptyState, ErrorState, PageHeader, PasswordField, SkeletonRows, Switch, TextField, Time } from '@/components/ui/ui';
import { useToast } from '@/components/ui/toast';
import { cn } from '@/lib/utils';

const KINDS: { id: MailboxKind; label: string; text: string }[] = [
  { id: 'imap', label: 'IMAP', text: 'Any mail server, over TLS. Use an app password where there is one.' },
  { id: 'graph', label: 'Microsoft 365', text: 'An app registration with the Mail.Read application permission, limited to this mailbox.' },
  { id: 'gmail', label: 'Gmail', text: 'Google Workspace: a service account with domain-wide delegation for gmail.readonly only.' },
];
const KIND_LABEL: Record<MailboxKind, string> = { imap: 'IMAP', graph: 'Microsoft 365', gmail: 'Gmail' };
const SECRET_LABEL: Record<MailboxKind, string> = { imap: 'Password', graph: 'Client secret', gmail: 'Service account key (JSON)' };

/** Where a mailbox is, in one line. */
export function whereOf(m: Pick<Mailbox, 'kind' | 'config'>): string {
  const c = m.config;
  if (m.kind === 'imap') return `${c.user ?? ''} at ${c.host ?? ''}:${c.port ?? ''} · ${c.folder ?? 'INBOX'}`;
  if (m.kind === 'graph') return `${c.address ?? ''} · ${c.folder ?? 'inbox'}`;
  return `${c.address ?? ''} · ${c.label ?? 'INBOX'}`;
}

function counts(m: Mailbox): string {
  const c = m.last_counts;
  const n = (v: number | undefined, one: string, many: string) => `${v ?? 0} ${(v ?? 0) === 1 ? one : many}`;
  return [n(c.imported, 'imported', 'imported'), n(c.duplicates, 'duplicate', 'duplicates'), n(c.skipped, 'skipped', 'skipped')].join(', ');
}

function StatusPill({ m }: { m: Mailbox }) {
  const [text, tone] = !m.enabled
    ? ['Off', 'border-line text-ink-muted']
    : m.status === 'ok'
      ? ['OK', 'border-accent/40 text-accent']
      : m.status === 'error'
        ? ['Error', 'border-v-malicious/40 text-v-malicious']
        : ['Not polled yet', 'border-line text-ink-muted'];
  return <span className={cn('rounded-full border px-2 py-0.5 text-[11px] font-medium', tone)}>{text}</span>;
}

type Draft = { kind: MailboxKind; name: string; interval: string; enabled: boolean; secret: string; config: MailboxConfig };

const emptyDraft = (kind: MailboxKind = 'imap'): Draft => ({ kind, name: '', interval: '5', enabled: true, secret: '', config: {} });
const draftOf = (m: Mailbox): Draft => ({ kind: m.kind, name: m.name, interval: String(m.interval_minutes), enabled: m.enabled, secret: '', config: { ...m.config } });

function MailboxDialog({ open, onOpenChange, editing, onSaved }: { open: boolean; onOpenChange: (o: boolean) => void; editing: Mailbox | null; onSaved: (m: Mailbox) => void }) {
  const [draft, setDraft] = useState<Draft>(emptyDraft());
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const keyId = useId();

  useEffect(() => {
    if (open) {
      setDraft(editing ? draftOf(editing) : emptyDraft());
      setError(null);
    } else {
      setDraft(emptyDraft()); // never keep a credential after the dialog closes
    }
  }, [open, editing]);

  const set = (patch: Partial<Draft>) => setDraft((d) => ({ ...d, ...patch }));
  const setConfig = (patch: MailboxConfig) => setDraft((d) => ({ ...d, config: { ...d.config, ...patch } }));
  const value = (key: keyof MailboxConfig) => String(draft.config[key] ?? '');

  async function submit(e: FormEvent) {
    e.preventDefault();
    const interval = Number(draft.interval);
    if (!draft.name.trim() || draft.name.trim().length > 48) return setError('Give the mailbox a name of 1 to 48 characters.');
    if (!Number.isInteger(interval) || interval < 5 || interval > 1440) return setError('Poll every 5 to 1,440 minutes.');
    if (!editing && !draft.secret) return setError(`${SECRET_LABEL[draft.kind]} is required.`);
    const config: MailboxConfig = { ...draft.config };
    delete config.service_account;
    if (config.port !== undefined && String(config.port) === '') delete config.port;
    setBusy(true);
    setError(null);
    try {
      const saved = editing
        ? await updateMailbox(editing.id, { name: draft.name.trim(), interval_minutes: interval, enabled: draft.enabled, config, ...(draft.secret ? { secret: draft.secret } : {}) })
        : await createMailbox({ name: draft.name.trim(), kind: draft.kind, interval_minutes: interval, config, secret: draft.secret });
      onSaved(saved);
      onOpenChange(false);
    } catch (err) {
      setError(err instanceof ApiError ? err.detail : NETWORK_MESSAGE);
    } finally {
      setBusy(false);
    }
  }

  const keep = editing ? 'Leave empty to keep the one stored.' : undefined;
  const ignore = { 'data-bwignore': 'true', 'data-1p-ignore': 'true', 'data-lpignore': 'true' };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[calc(100dvh-32px)] w-[min(560px,calc(100vw-32px))] overflow-y-auto rounded-[24px] border border-line-strong bg-raised p-6 text-ink backdrop:bg-black/60">
        <DialogHeader>
          <DialogTitle className="text-lg font-semibold text-ink">{editing ? `Change ${editing.name}` : 'Add a mailbox'}</DialogTitle>
          <DialogDescription className="text-sm text-ink-dim">PhishHawk reads it and changes nothing: no message is marked read, moved or deleted.</DialogDescription>
        </DialogHeader>
        <form className="mt-5 grid gap-4" onSubmit={submit} noValidate>
          {!editing && (
            <fieldset className="grid gap-2">
              <legend className="mb-1.5 text-[13px] font-medium text-ink-dim">Kind</legend>
              {KINDS.map((k) => (
                <label key={k.id} className={cn('flex cursor-pointer items-start gap-3 rounded-2xl border px-4 py-3 text-sm', draft.kind === k.id ? 'border-accent/50 bg-accent/5' : 'border-line')}>
                  <input type="radio" name="kind" checked={draft.kind === k.id} onChange={() => setDraft({ ...emptyDraft(k.id), name: draft.name, interval: draft.interval })} className="mt-0.5 accent-[var(--accent)]" />
                  <span>
                    <span className="block font-medium text-ink">{k.label}</span>
                    <span className="block text-xs text-ink-muted">{k.text}</span>
                  </span>
                </label>
              ))}
            </fieldset>
          )}
          <TextField {...ignore} label="Name" value={draft.name} onChange={(e) => set({ name: e.target.value })} placeholder="Phish reports" maxLength={48} />
          {draft.kind === 'imap' && (
            <>
              <TextField {...ignore} label="Host" value={value('host')} onChange={(e) => setConfig({ host: e.target.value })} placeholder="imap.example.com" autoCapitalize="off" spellCheck={false} />
              <div className="grid gap-4 sm:grid-cols-2">
                <TextField {...ignore} label="Port" inputMode="numeric" value={value('port')} onChange={(e) => setConfig({ port: e.target.value === '' ? undefined : Number(e.target.value) })} placeholder={draft.config.starttls ? '143' : '993'} />
                <TextField {...ignore} label="Folder" value={value('folder')} onChange={(e) => setConfig({ folder: e.target.value })} placeholder="INBOX" />
              </div>
              <Switch checked={Boolean(draft.config.starttls)} onChange={(starttls) => setConfig({ starttls })} label="STARTTLS" description="Off: TLS from the start (port 993). On: STARTTLS (port 143). Never without TLS." />
              <TextField {...ignore} label="User" value={value('user')} onChange={(e) => setConfig({ user: e.target.value })} autoComplete="off" autoCapitalize="off" spellCheck={false} />
            </>
          )}
          {draft.kind === 'graph' && (
            <>
              <TextField {...ignore} label="Tenant ID or domain" value={value('tenant_id')} onChange={(e) => setConfig({ tenant_id: e.target.value })} placeholder="contoso.onmicrosoft.com" autoCapitalize="off" spellCheck={false} />
              <TextField {...ignore} label="Application (client) ID" value={value('client_id')} onChange={(e) => setConfig({ client_id: e.target.value })} autoCapitalize="off" spellCheck={false} />
              <TextField {...ignore} label="Report mailbox" type="email" value={value('address')} onChange={(e) => setConfig({ address: e.target.value })} placeholder="phish@example.com" />
              <TextField {...ignore} label="Folder" value={value('folder')} onChange={(e) => setConfig({ folder: e.target.value })} placeholder="inbox" />
            </>
          )}
          {draft.kind === 'gmail' && (
            <>
              <TextField {...ignore} label="Report mailbox" type="email" value={value('address')} onChange={(e) => setConfig({ address: e.target.value })} placeholder="phish@example.com" />
              <TextField {...ignore} label="Label" value={value('label')} onChange={(e) => setConfig({ label: e.target.value })} placeholder="INBOX" />
              {editing?.config.service_account && <p className="text-xs text-ink-muted">Service account: <span className="break-all font-mono">{editing.config.service_account}</span></p>}
            </>
          )}
          {draft.kind === 'gmail' ? (
            <div className="grid gap-1.5">
              <label htmlFor={keyId} className="text-[13px] font-medium text-ink-dim">{SECRET_LABEL.gmail}</label>
              <textarea
                id={keyId}
                rows={4}
                value={draft.secret}
                onChange={(e) => set({ secret: e.target.value })}
                placeholder={editing ? 'Leave empty to keep the key stored.' : 'Paste the contents of the JSON key file.'}
                spellCheck={false}
                autoComplete="off"
                className="block w-full resize-y rounded-[14px] border border-line-strong bg-raised px-3.5 py-3 font-mono text-[12px] leading-relaxed text-ink placeholder:text-ink-muted focus:border-accent/60 focus:outline-none"
              />
            </div>
          ) : (
            <PasswordField {...ignore} label={SECRET_LABEL[draft.kind]} value={draft.secret} onChange={(e) => set({ secret: e.target.value })} autoComplete="new-password" hint={keep} />
          )}
          <TextField {...ignore} label="Minutes between polls" inputMode="numeric" value={draft.interval} onChange={(e) => set({ interval: e.target.value })} hint="5 or more. After a failure, polling waits longer, up to an hour." />
          {editing && <Switch checked={draft.enabled} onChange={(enabled) => set({ enabled })} label="Poll this mailbox" />}
          {error && <p className="text-sm text-v-malicious" role="alert">{error}</p>}
          <div className="mt-2 flex justify-end gap-2">
            <Button size="sm" variant="ghost" onClick={() => onOpenChange(false)} disabled={busy}>Cancel</Button>
            <Button size="sm" variant="primary" type="submit" disabled={busy}>{editing ? 'Save' : 'Add mailbox'}</Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}

function MailboxRow({ m, onPoll, onEdit, onDelete, polling }: { m: Mailbox; onPoll: () => void; onEdit: () => void; onDelete: () => void; polling: boolean }) {
  return (
    <div className="grid gap-3 px-5 py-4 sm:grid-cols-[minmax(0,1fr)_auto] sm:items-start">
      <div className="min-w-0">
        <p className="flex flex-wrap items-center gap-2 text-sm font-medium text-ink">
          <span className="[overflow-wrap:anywhere]">{m.name}</span>
          <span className="rounded-full border border-line px-2 py-0.5 text-[11px] font-normal text-ink-dim">{KIND_LABEL[m.kind]}</span>
          <StatusPill m={m} />
        </p>
        <p className="mt-1 font-mono text-xs text-ink-muted [overflow-wrap:anywhere]">{whereOf(m)}</p>
        {m.status === 'error' && m.error && <p className="mt-2 break-words text-[13px] text-v-malicious">{m.error}</p>}
        <p className="mt-2 text-xs text-ink-muted">
          {m.last_poll_at ? (
            <>
              Last poll <Time iso={m.last_poll_at} relative />: {counts(m)}
            </>
          ) : (
            'Not polled yet'
          )}
          {m.enabled && m.next_poll_at && (
            <>
              {' · '}next <Time iso={m.next_poll_at} relative />
            </>
          )}
        </p>
      </div>
      <div className="flex flex-wrap gap-2 sm:justify-end">
        <Button size="sm" onClick={onPoll} disabled={!m.enabled || polling}>
          <RefreshCw className={cn('h-3.5 w-3.5', polling && 'animate-spin motion-reduce:animate-none')} strokeWidth={1.75} /> Poll now
        </Button>
        <Button size="sm" variant="ghost" onClick={onEdit} aria-label={`Change ${m.name}`}>
          <Pencil className="h-3.5 w-3.5" strokeWidth={1.75} /> Change
        </Button>
        <Button size="sm" variant="ghost" onClick={onDelete} aria-label={`Delete ${m.name}`}>
          <Trash2 className="h-3.5 w-3.5" strokeWidth={1.75} /> Delete
        </Button>
      </div>
    </div>
  );
}

export default function MailboxesScreen() {
  const toast = useToast();
  const [rows, setRows] = useState<Mailbox[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [attempt, setAttempt] = useState(0);
  const [dialog, setDialog] = useState<{ open: boolean; editing: Mailbox | null }>({ open: false, editing: null });
  const [removing, setRemoving] = useState<Mailbox | null>(null);
  const [busy, setBusy] = useState(false);
  const [removeError, setRemoveError] = useState<string | null>(null);
  const [polling, setPolling] = useState<number | null>(null);

  const refresh = (signal?: AbortSignal) =>
    listMailboxes(signal)
      .then(setRows)
      .catch((e) => !isAbort(e) && setError(e instanceof ApiError ? e.detail : NETWORK_MESSAGE));

  useEffect(() => {
    const controller = new AbortController();
    setError(null);
    refresh(controller.signal);
    // the status changes as the worker polls: ask again every 15 seconds while the page is open
    const timer = setInterval(() => refresh(controller.signal), 15_000);
    return () => {
      controller.abort();
      clearInterval(timer);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [attempt]);

  async function pollNow(m: Mailbox) {
    setPolling(m.id);
    try {
      const { queued } = await pollMailbox(m.id);
      toast(queued ? `Polling ${m.name}.` : `A poll of ${m.name} is already waiting.`);
      setTimeout(() => refresh(), 3000);
    } catch (e) {
      toast(e instanceof ApiError ? e.detail : NETWORK_MESSAGE);
    } finally {
      setPolling(null);
    }
  }

  return (
    <div className="grid max-w-5xl grid-cols-1 gap-8">
      <PageHeader
        eyebrow="Mailboxes"
        title="Report mailboxes"
        description="PhishHawk reads these mailboxes and changes nothing in them. Each new message is analysed as an upload is, and none twice."
        actions={
          <Button variant="primary" onClick={() => setDialog({ open: true, editing: null })} disabled={!rows}>
            <Plus className="h-4 w-4" strokeWidth={1.75} /> Add mailbox
          </Button>
        }
      />
      {error ? (
        <ErrorState detail={error} onRetry={() => setAttempt((a) => a + 1)} />
      ) : !rows ? (
        <SkeletonRows rows={2} />
      ) : rows.length === 0 ? (
        <EmptyState
          title="No mailbox yet. Connect the mailbox people report phishing to, and every report is analysed as it arrives."
          action={
            <Button size="sm" onClick={() => setDialog({ open: true, editing: null })}>
              <MailboxIcon className="h-4 w-4" strokeWidth={1.75} /> Add mailbox
            </Button>
          }
        />
      ) : (
        <ul className="grid grid-cols-1 gap-4">
          {rows.map((m) => (
            <li key={m.id}>
              <Card className="overflow-hidden">
                <MailboxRow m={m} polling={polling === m.id} onPoll={() => pollNow(m)} onEdit={() => setDialog({ open: true, editing: m })} onDelete={() => setRemoving(m)} />
              </Card>
            </li>
          ))}
        </ul>
      )}

      <MailboxDialog
        open={dialog.open}
        editing={dialog.editing}
        onOpenChange={(open) => setDialog((d) => ({ ...d, open }))}
        onSaved={(saved) => {
          toast(dialog.editing ? 'Mailbox saved.' : `${saved.name} added. The first poll imports its newest 50 messages.`);
          refresh();
        }}
      />
      <ConfirmDialog
        open={removing !== null}
        onOpenChange={(open) => {
          if (!open) {
            setRemoving(null);
            setRemoveError(null);
          }
        }}
        title={`Delete ${removing?.name ?? 'this mailbox'}?`}
        body="PhishHawk stops reading it and forgets its credential. The messages it imported stay, with their analyses."
        confirmLabel="Delete"
        danger
        busy={busy}
        error={removeError}
        onConfirm={async () => {
          setBusy(true);
          setRemoveError(null);
          try {
            await deleteMailbox(removing!.id);
            await refresh();
            toast('Mailbox deleted.');
            setRemoving(null);
          } catch (e) {
            setRemoveError(e instanceof ApiError ? e.detail : NETWORK_MESSAGE);
          } finally {
            setBusy(false);
          }
        }}
      />
    </div>
  );
}
