/* The signed-in user, as the server reports it. This is the only place the app
   gets the username and role: never from the login form, a URL or storage. */

import { useCallback, useEffect, useState } from 'react';
import { getSession, login, logout, onUnauthorized } from '@/api/client';
import { ApiError, NETWORK_MESSAGE, isAbort } from '@/api/errors';
import type { Session } from '@/api/types';

export type Auth =
  | { status: 'checking' }
  | { status: 'unreachable'; detail: string }
  | { status: 'signed-out'; expired: boolean }
  | { status: 'signed-in'; session: Session };

export function useAuth() {
  const [auth, setAuth] = useState<Auth>({ status: 'checking' });

  const check = useCallback((signal?: AbortSignal) => {
    setAuth({ status: 'checking' });
    getSession(signal)
      .then((session) => setAuth({ status: 'signed-in', session }))
      .catch((error: unknown) => {
        if (isAbort(error)) return;
        if (error instanceof ApiError && error.status === 401) setAuth({ status: 'signed-out', expired: false });
        else setAuth({ status: 'unreachable', detail: error instanceof ApiError ? error.detail : NETWORK_MESSAGE });
      });
  }, []);

  useEffect(() => {
    // Any later 401 means the session ended: show the login with "Your session has ended".
    onUnauthorized(() => setAuth((current) => ({ status: 'signed-out', expired: current.status === 'signed-in' })));
    const controller = new AbortController();
    check(controller.signal);
    return () => controller.abort();
  }, [check]);

  /** Throws ApiError: 401 wrong details, 429 throttled (see retryAfter), status 0 unreachable. */
  const signIn = useCallback(async (username: string, password: string) => {
    const session = await login(username, password);
    setAuth({ status: 'signed-in', session });
    return session;
  }, []);

  /** Signed in by setup, sign-up or an invitation: the server already opened the session. */
  const enter = useCallback((session: Session) => setAuth({ status: 'signed-in', session }), []);

  /** Reads the session again (after the profile or the organization's name changed), without a loading screen. */
  const refresh = useCallback(async () => {
    try {
      setAuth({ status: 'signed-in', session: await getSession() });
    } catch {
      // a 401 already reached the handler above; anything else leaves the session as it was
    }
  }, []);

  const signOut = useCallback(async () => {
    try {
      await logout();
    } catch {
      // signed out here either way; the server session expires on its own
    } finally {
      setAuth({ status: 'signed-out', expired: false });
    }
  }, []);

  const retry = useCallback(() => check(), [check]);

  return { auth, signIn, signOut, retry, enter, refresh };
}
