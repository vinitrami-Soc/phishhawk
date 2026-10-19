/* Whether this server still waits for its owner (setup), whether anyone may
   create an account (sign-up), and whether it sends mail, so a forgotten
   password can be reset (reset). Each is asked once when a page that offers them
   shows; null until the answers are in. A server that cannot be asked offers
   none of them. */

import { useEffect, useState } from 'react';
import { getResetState, getSetupState, getSignupState } from '@/api/client';

type GettingIn = { setup: boolean; signup: boolean; reset: boolean };

export function useGettingIn(): GettingIn | null {
  const [state, setState] = useState<GettingIn | null>(null);
  useEffect(() => {
    const controller = new AbortController();
    const closed = { open: false };
    Promise.all([
      getSetupState(controller.signal).catch(() => closed),
      getSignupState(controller.signal).catch(() => closed),
      getResetState(controller.signal).catch(() => ({ available: false })),
    ]).then(([setup, signup, reset]) => {
      if (!controller.signal.aborted) setState({ setup: setup.open, signup: signup.open, reset: reset.available });
    });
    return () => controller.abort();
  }, []);
  return state;
}

/** Whether this server sends mail: then sign-up and joining need an email address. False until it says so. */
export function useSendsMail(): boolean {
  const [sends, setSends] = useState(false);
  useEffect(() => {
    const controller = new AbortController();
    getResetState(controller.signal)
      .then((state) => !controller.signal.aborted && setSends(state.available))
      .catch(() => undefined);
    return () => controller.abort();
  }, []);
  return sends;
}
