/* Settings checks, the same as the server's (PATCH /api/v1/settings answers 422
   otherwise), so a mistake shows next to the field before anything is saved. */

const DOMAIN = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$/;

/** The domain as the server keeps it (lower case, IDNA, no final dot), or null. */
export function normaliseDomain(value: string): string | null {
  const name = value.trim().toLowerCase().replace(/\.$/, '');
  if (!name || /[\s/:@?#[\]\\]/.test(name)) return null;
  let host: string;
  try {
    host = new URL(`http://${name}`).hostname; // the browser's own IDNA conversion
  } catch {
    return null;
  }
  return host.length <= 253 && DOMAIN.test(host) ? host : null;
}

/** A limit: a whole number from 1 to 100000, or null. */
export function parseLimit(value: string): number | null {
  const text = value.trim();
  if (!/^\d{1,6}$/.test(text)) return null;
  const number = Number(text);
  return number >= 1 && number <= 100000 ? number : null;
}
