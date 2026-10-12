/* The light/dark switch, fixed at the bottom left of every screen. The knob
   slides with a spring; the new theme grows in from the switch as a circle. */

import { motion } from 'motion/react';
import { Moon, Sun } from 'lucide-react';
import { setTheme, useTheme } from '@/app/theme';
import { cn } from '@/lib/utils';

export function ThemeToggle({ className }: { className?: string } = {}) {
  const dark = useTheme() === 'dark';
  return (
    <button
      type="button"
      role="switch"
      aria-checked={dark}
      aria-label="Dark theme"
      title={dark ? 'Switch to the light theme' : 'Switch to the dark theme'}
      onClick={(event) => {
        const box = event.currentTarget.getBoundingClientRect();
        setTheme(dark ? 'light' : 'dark', { x: box.left + box.width / 2, y: box.top + box.height / 2 });
      }}
      className={cn(
        "rounded-full border border-line-strong bg-raised/85 p-1 shadow-[var(--float-shadow)] backdrop-blur-xl transition-transform duration-300 ease-[cubic-bezier(0.32,0.72,0,1)] active:scale-[0.97]",
        className ?? "fixed bottom-[max(16px,env(safe-area-inset-bottom))] left-4 z-40 h-11 w-[84px]"
      )}
    >
      <span className="relative grid h-full w-full grid-cols-2">
        <motion.span
          aria-hidden="true"
          className="absolute inset-y-0 left-0 w-1/2 rounded-full [background:var(--pill-active-bg)] shadow-[0_6px_16px_-8px_rgba(0,0,0,0.6)]"
          initial={false}
          animate={{ x: dark ? '100%' : '0%' }}
          transition={{ type: 'spring', bounce: 0.25, duration: 0.5 }}
        />
        <span className={cn('relative z-10 grid place-items-center transition-colors duration-300', dark ? 'text-ink-muted' : 'text-[var(--pill-active-ink)]')}>
          <Sun className="h-4 w-4" strokeWidth={1.75} aria-hidden="true" />
        </span>
        <span className={cn('relative z-10 grid place-items-center transition-colors duration-300', dark ? 'text-[var(--pill-active-ink)]' : 'text-ink-muted')}>
          <Moon className="h-4 w-4" strokeWidth={1.75} aria-hidden="true" />
        </span>
      </span>
    </button>
  );
}
