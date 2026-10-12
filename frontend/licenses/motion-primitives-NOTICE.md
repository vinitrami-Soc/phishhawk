# motion-primitives

The files in `src/components/core/`, `src/hooks/useClickOutside.tsx`,
`src/hooks/usePreventScroll.tsx` and `src/lib/utils.ts` come from
motion-primitives by ibelick (https://github.com/ibelick/motion-primitives,
https://motion-primitives.com), fetched from the `main` branch on 2026-10-09.
The project's README states: "Licensed under the MIT license."

Changes made for PhishHawk:

- `src/components/core/text-morph.tsx`: `AnimatePresence mode='popLayout'`
  became `mode='sync'`.
- `src/components/core/transition-panel.tsx`: `mode='popLayout'` became
  `mode='wait'`.

Reason: in `popLayout` mode, motion inserts a `<style>` element to position the
exiting element. PhishHawk's Content-Security-Policy (`style-src 'self'`)
refuses it, which shows as "Refused to apply inline style" in the console.
Every other file is unchanged.
