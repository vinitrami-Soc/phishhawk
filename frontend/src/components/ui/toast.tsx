/* Short, transient results ("Copied", "Hold released"). Errors that need action
   stay inline on the screen, not here. */

import { createContext, useCallback, useContext, useState, type ReactNode } from 'react';
import { AnimatePresence, motion } from 'motion/react';

const ToastContext = createContext<(message: string) => void>(() => {});

export function useToast() {
  return useContext(ToastContext);
}

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toast, setToast] = useState<{ id: number; message: string } | null>(null);
  const show = useCallback((message: string) => {
    const id = Date.now();
    setToast({ id, message });
    setTimeout(() => setToast((current) => (current?.id === id ? null : current)), 2600);
  }, []);
  return (
    <ToastContext.Provider value={show}>
      {children}
      <div role="status" aria-live="polite" className="pointer-events-none fixed inset-x-0 bottom-20 z-50 flex justify-center px-4 md:bottom-6 md:justify-end md:px-6">
        <AnimatePresence mode="wait">
          {toast && (
            <motion.div
              key={toast.id}
              initial={{ opacity: 0, y: 12 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: 8 }}
              transition={{ duration: 0.24, ease: [0.32, 0.72, 0, 1] }}
              className="rounded-full border border-line-strong bg-raised px-4 py-2.5 text-sm text-ink shadow-[var(--float-shadow)]"
            >
              {toast.message}
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </ToastContext.Provider>
  );
}
