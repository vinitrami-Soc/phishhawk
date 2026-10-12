/* "Back to top": shows after a screen and a half of scrolling. It also moves the
   focus to the start of the main content, so keyboard users land there too.
   `raised` lifts it above the phone action bar on the Analysis page. */

import { useEffect, useState } from 'react';
import { AnimatePresence, motion, useReducedMotion } from 'motion/react';
import { ArrowUp } from 'lucide-react';
import { cn } from '@/lib/utils';

export function BackToTop({ raised = false }: { raised?: boolean }) {
  const [shown, setShown] = useState(false);
  const reduce = useReducedMotion();

  useEffect(() => {
    let frame = 0;
    const check = () => {
      frame = 0;
      setShown(window.scrollY > window.innerHeight * 1.5);
    };
    const schedule = () => {
      if (!frame) frame = requestAnimationFrame(check);
    };
    check();
    window.addEventListener('scroll', schedule, { passive: true });
    window.addEventListener('resize', schedule);
    return () => {
      window.removeEventListener('scroll', schedule);
      window.removeEventListener('resize', schedule);
      cancelAnimationFrame(frame);
    };
  }, []);

  return (
    <AnimatePresence>
      {shown && (
        <motion.button
          type="button"
          aria-label="Back to top"
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          exit={{ opacity: 0, y: 8 }}
          transition={{ duration: 0.2, ease: [0.32, 0.72, 0, 1] }}
          onClick={() => {
            window.scrollTo({ top: 0, behavior: reduce ? 'auto' : 'smooth' });
            document.getElementById('main')?.focus({ preventScroll: true });
          }}
          className={cn(
            'fixed right-4 z-40 grid h-11 w-11 place-items-center rounded-full border border-line-strong bg-raised/85 text-ink-dim shadow-[var(--float-shadow)] backdrop-blur-xl transition-colors hover:text-ink print:hidden',
            raised ? 'bottom-[calc(max(16px,env(safe-area-inset-bottom))+56px)] lg:bottom-[max(16px,env(safe-area-inset-bottom))]' : 'bottom-[max(16px,env(safe-area-inset-bottom))]',
          )}
        >
          <ArrowUp className="h-4 w-4" strokeWidth={1.75} />
        </motion.button>
      )}
    </AnimatePresence>
  );
}
