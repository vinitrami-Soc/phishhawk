/* Whether this server still waits for its owner (setup), and whether anyone may
   create an account (sign-up). Each is asked once when a page that offers them
   shows; null until both answers are in. A server that cannot be asked offers
   neither. */

import { useEffect, useState } from 'react';
import { getSetupState, getSignupState } from '@/api/client';

export function useGettingIn(): { setup: boolean; signup: boolean } | null {
  const [state, setState] = useState<{ setup: boolean; signup: boolean } | null>(null);
  useEffect(() => {
    const controller = new AbortController();
    const closed = { open: false };
    Promise.all([getSetupState(controller.signal).catch(() => closed), getSignupState(controller.signal).catch(() => closed)]).then(([setup, signup]) => {
      if (!controller.signal.aborted) setState({ setup: setup.open, signup: signup.open });
    });
    return () => controller.abort();
  }, []);
  return state;
}
