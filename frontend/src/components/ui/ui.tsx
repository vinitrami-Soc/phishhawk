/* The app's building blocks. Colours come from the theme tokens only, so
   everything here works in light and dark. */

import { useEffect, useId, useState, type ButtonHTMLAttributes, type InputHTMLAttributes, type ReactNode } from 'react';
import { AlertTriangle, CircleCheck, Copy, Eye, EyeOff, OctagonAlert, ShieldAlert, ShieldQuestion } from 'lucide-react';
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from '@/components/core/dialog';
import { TextMorph } from '@/components/core/text-morph';
import { cn } from '@/lib/utils';
import { formatDateTime, formatRelative } from '@/lib/format';
import { SEVERITY_TONE, verdictTone } from '@/app/vocabulary';
import type { Severity } from '@/api/types';

export const EASE = 'ease-[cubic-bezier(0.32,0.72,0,1)]';

/* ---- surfaces ---- */

/** The double-bezel card: a tray with a hairline, and the content plate inside it. */
export function Panel({ children, className, inner }: { children: ReactNode; className?: string; inner?: string }) {
  return (
    <div className={cn('rounded-[28px] border border-line bg-sunken/70 p-1.5', className)}>
      <div className={cn('h-full rounded-[22px] border border-line bg-surface shadow-[var(--shell-highlight)]', inner)}>
        {children}
      </div>
    </div>
  );
}

/** A flat card for content inside a page. */
export function Card({ children, className }: { children: ReactNode; className?: string }) {
  return <div className={cn('rounded-[20px] border border-line bg-surface', className)}>{children}</div>;
}

export function SectionTitle({ children, aside }: { children: ReactNode; aside?: ReactNode }) {
  return (
    <div className="flex items-baseline justify-between gap-3">
      <h2 className="text-[15px] font-semibold tracking-tight text-ink">{children}</h2>
      {aside && <div className="text-xs text-ink-muted">{aside}</div>}
    </div>
  );
}

export function PageHeader({ eyebrow, title, description, actions }: { eyebrow: string; title: string; description?: ReactNode; actions?: ReactNode }) {
  return (
    <header className="flex flex-wrap items-end justify-between gap-4">
      <div className="min-w-0">
        <span className="inline-flex rounded-full border border-line bg-surface px-3 py-1 text-[10px] font-medium uppercase tracking-[0.2em] text-ink-muted">
          {eyebrow}
        </span>
        <h1 className="mt-3 text-[28px] font-semibold leading-tight tracking-[-0.02em] text-ink md:text-[32px]">{title}</h1>
        {description && <p className="mt-1.5 max-w-[60ch] text-sm text-ink-dim">{description}</p>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </header>
  );
}

/* ---- buttons ---- */

type ButtonProps = ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: 'primary' | 'secondary' | 'ghost' | 'danger';
  size?: 'sm' | 'md';
};

export function Button({ variant = 'secondary', size = 'md', className, children, type = 'button', ...rest }: ButtonProps) {
  return (
    <button
      type={type}
      className={cn(
        'inline-flex items-center justify-center gap-2 whitespace-nowrap rounded-full font-medium transition-[transform,background-color,color,border-color,opacity] duration-300 active:scale-[0.98] disabled:pointer-events-none disabled:opacity-45',
        EASE,
        size === 'md' ? 'h-11 px-5 text-sm' : 'h-9 px-4 text-[13px]',
        variant === 'primary' && '[background:var(--pill-active-bg)] text-[var(--pill-active-ink)] shadow-[var(--float-shadow)]',
        variant === 'secondary' && 'border border-line-strong bg-raised text-ink hover:bg-hover',
        variant === 'ghost' && 'text-ink-dim hover:bg-hover hover:text-ink',
        variant === 'danger' && 'border border-v-malicious/35 bg-v-malicious/10 text-v-malicious hover:bg-v-malicious/15',
        className,
      )}
      {...rest}
    >
      {children}
    </button>
  );
}

/* ---- badges ---- */

const VERDICT_ICON = {
  MALICIOUS: OctagonAlert,
  'LIKELY PHISHING': AlertTriangle,
  SUSPICIOUS: ShieldQuestion,
  'NO STRONG INDICATORS': ShieldAlert,
} as const;

export function VerdictBadge({ verdict, className }: { verdict: string; className?: string }) {
  const t = verdictTone(verdict);
  const Icon = VERDICT_ICON[verdict as keyof typeof VERDICT_ICON] ?? ShieldAlert;
  return (
    <span className={cn('inline-flex shrink-0 items-center gap-1.5 whitespace-nowrap rounded-full border px-2.5 py-1 text-[11px] font-semibold uppercase tracking-[0.04em]', t.text, t.tint, t.ring, className)}>
      <Icon className="h-3.5 w-3.5" strokeWidth={1.75} aria-hidden="true" />
      {verdict}
    </span>
  );
}

export function SeverityBadge({ severity }: { severity: Severity | string }) {
  const t = SEVERITY_TONE[severity as Severity];
  return (
    <span className={cn('inline-flex shrink-0 rounded-full border px-2 py-0.5 text-[10px] font-semibold uppercase tracking-[0.06em]', t ? [t.text, t.tint, t.ring] : 'border-line text-ink-muted')}>
      {severity}
    </span>
  );
}

export function Chip({ children, className }: { children: ReactNode; className?: string }) {
  return <span className={cn('inline-flex items-center rounded-full border border-line bg-raised px-2.5 py-0.5 text-xs text-ink-dim', className)}>{children}</span>;
}

/* ---- text helpers ---- */

export function middle(value: string, keep = 10) {
  return value.length > keep * 2 + 1 ? `${value.slice(0, keep)}…${value.slice(-keep)}` : value;
}

export function Time({ iso, relative = false, className }: { iso: string | null | undefined; relative?: boolean; className?: string }) {
  if (!iso) return null;
  return (
    <time dateTime={iso} title={formatDateTime(iso)} className={className}>
      {relative ? formatRelative(iso) : formatDateTime(iso)}
    </time>
  );
}

/** Copies exactly the text given (the defanged text shown on screen). */
export function CopyButton({ text, label = 'Copy', className }: { text: string; label?: string; className?: string }) {
  const [state, setState] = useState<'idle' | 'done' | 'failed'>('idle');
  useEffect(() => {
    if (state === 'idle') return;
    const t = setTimeout(() => setState('idle'), 1600);
    return () => clearTimeout(t);
  }, [state]);
  return (
    <button
      type="button"
      onClick={async () => {
        try {
          if (!navigator.clipboard) throw new Error('no clipboard');
          await navigator.clipboard.writeText(text);
          setState('done');
        } catch {
          setState('failed');
        }
      }}
      className={cn('inline-flex h-8 shrink-0 items-center gap-1.5 rounded-full border border-line px-2.5 text-xs text-ink-dim transition-colors hover:bg-hover hover:text-ink', className)}
      aria-label={`${label}: ${text}`}
    >
      {state === 'done' ? <CircleCheck className="h-3.5 w-3.5 text-ok" strokeWidth={1.75} /> : <Copy className="h-3.5 w-3.5" strokeWidth={1.75} />}
      <TextMorph>{state === 'done' ? 'Copied' : state === 'failed' ? 'Select to copy' : 'Copy'}</TextMorph>
    </button>
  );
}

/* ---- form controls ---- */

export function Switch({ checked, onChange, label, description, disabled }: { checked: boolean; onChange: (next: boolean) => void; label: string; description?: ReactNode; disabled?: boolean }) {
  const id = useId();
  return (
    <div className="flex items-start justify-between gap-6">
      <div className="min-w-0">
        <label htmlFor={id} className="text-sm font-medium text-ink">
          {label}
        </label>
        {description && <div className="mt-0.5 text-[13px] text-ink-muted">{description}</div>}
      </div>
      <button
        id={id}
        type="button"
        role="switch"
        aria-checked={checked}
        disabled={disabled}
        onClick={() => onChange(!checked)}
        className={cn(
          'relative mt-0.5 h-7 w-12 shrink-0 rounded-full border transition-colors duration-300 disabled:opacity-45',
          EASE,
          checked ? 'border-transparent bg-accent' : 'border-line-strong bg-sunken',
        )}
      >
        <span
          aria-hidden="true"
          className={cn(
            'absolute left-0.5 top-0.5 h-[22px] w-[22px] rounded-full bg-white shadow-[0_2px_6px_rgba(0,0,0,0.35)] transition-transform duration-300',
            EASE,
            checked ? 'translate-x-5' : 'translate-x-0',
          )}
        />
      </button>
    </div>
  );
}

export function TextField({ label, hint, error, className, ...rest }: InputHTMLAttributes<HTMLInputElement> & { label: string; hint?: ReactNode; error?: string | null }) {
  const id = useId();
  return (
    <div className={cn('grid gap-1.5', className)}>
      <label htmlFor={id} className="text-[13px] font-medium text-ink-dim">
        {label}
      </label>
      <input
        id={id}
        aria-invalid={error ? true : undefined}
        aria-describedby={hint || error ? `${id}-note` : undefined}
        className="h-11 w-full rounded-[14px] border border-line-strong bg-raised px-3.5 text-sm text-ink placeholder:text-ink-muted transition-colors focus:border-accent/60 focus:outline-none focus-visible:outline-2 focus-visible:outline-accent"
        {...rest}
      />
      {(error || hint) && (
        <p id={`${id}-note`} className={cn('text-xs', error ? 'text-v-malicious' : 'text-ink-muted')} role={error ? 'alert' : undefined}>
          {error ?? hint}
        </p>
      )}
    </div>
  );
}

/** A password field with a button that shows or hides what was typed. */
export function PasswordField({ label, hint, error, className, ...rest }: Omit<InputHTMLAttributes<HTMLInputElement>, 'type'> & { label: string; hint?: ReactNode; error?: string | null }) {
  const id = useId();
  const [show, setShow] = useState(false);
  return (
    <div className={cn('grid gap-1.5', className)}>
      <label htmlFor={id} className="text-[13px] font-medium text-ink-dim">
        {label}
      </label>
      <div className="relative">
        <input
          id={id}
          type={show ? 'text' : 'password'}
          aria-invalid={error ? true : undefined}
          aria-describedby={hint || error ? `${id}-note` : undefined}
          className="h-11 w-full rounded-[14px] border border-line-strong bg-raised pl-3.5 pr-12 text-sm text-ink placeholder:text-ink-muted transition-colors focus:border-accent/60 focus:outline-none focus-visible:outline-2 focus-visible:outline-accent"
          {...rest}
        />
        <button
          type="button"
          onClick={() => setShow((s) => !s)}
          aria-label={show ? 'Hide password' : 'Show password'}
          aria-controls={id}
          className="absolute right-1 top-1 grid h-9 w-9 place-items-center rounded-full text-ink-muted hover:bg-hover hover:text-ink"
        >
          {show ? <EyeOff className="h-4 w-4" strokeWidth={1.5} /> : <Eye className="h-4 w-4" strokeWidth={1.5} />}
        </button>
      </div>
      {(error || hint) && (
        <p id={`${id}-note`} className={cn('text-xs', error ? 'text-v-malicious' : 'text-ink-muted')} role={error ? 'alert' : undefined}>
          {error ?? hint}
        </p>
      )}
    </div>
  );
}

/* ---- states ---- */

export function Skeleton({ className }: { className?: string }) {
  return <div className={cn('animate-pulse rounded-lg bg-hover motion-reduce:animate-none', className)} />;
}

export function SkeletonRows({ rows = 6 }: { rows?: number }) {
  return (
    <div className="grid gap-2" aria-busy="true" aria-label="Loading">
      {Array.from({ length: rows }, (_, i) => (
        <Skeleton key={i} className="h-14 rounded-2xl" />
      ))}
    </div>
  );
}

export function EmptyState({ title, action }: { title: string; action?: ReactNode }) {
  return (
    <Card className="grid place-items-center gap-3 px-6 py-14 text-center">
      <p className="text-sm text-ink-dim">{title}</p>
      {action}
    </Card>
  );
}

export function ErrorState({ detail, onRetry }: { detail: string; onRetry?: () => void }) {
  return (
    <Card className="grid place-items-center gap-3 border-v-malicious/25 px-6 py-12 text-center" >
      <p className="max-w-[56ch] text-sm text-ink" role="alert">
        {detail}
      </p>
      {onRetry && (
        <Button size="sm" onClick={onRetry}>
          Try again
        </Button>
      )}
    </Card>
  );
}

/* ---- confirmation ---- */

export function ConfirmDialog({
  open,
  onOpenChange,
  title,
  body,
  confirmLabel,
  danger,
  busy,
  error,
  onConfirm,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: string;
  body: ReactNode;
  confirmLabel: string;
  danger?: boolean;
  busy?: boolean;
  error?: string | null;
  onConfirm: () => void;
}) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="w-[min(460px,calc(100vw-32px))] rounded-[24px] border border-line-strong bg-raised p-6 text-ink shadow-[var(--float-shadow)] backdrop:bg-black/60">
        <DialogHeader>
          <DialogTitle className="text-lg font-semibold tracking-tight text-ink">{title}</DialogTitle>
          <DialogDescription className="text-sm leading-relaxed text-ink-dim">{body}</DialogDescription>
        </DialogHeader>
        {error && (
          <p className="mt-4 text-sm text-v-malicious" role="alert">
            {error}
          </p>
        )}
        <div className="mt-6 flex justify-end gap-2">
          <Button size="sm" variant="ghost" onClick={() => onOpenChange(false)} disabled={busy}>
            Cancel
          </Button>
          <Button size="sm" variant={danger ? 'danger' : 'primary'} onClick={onConfirm} disabled={busy}>
            {confirmLabel}
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}
