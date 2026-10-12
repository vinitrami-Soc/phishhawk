/* What locked.test.ts compares: a file's code without comments and formatting
   (or, for JSON, its data with sorted keys). */

function canonical(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.keys(value as Record<string, unknown>)
        .sort()
        .map((key) => [key, canonical((value as Record<string, unknown>)[key])]),
    );
  }
  return value;
}

export function fingerprint(path: string, text: string): string {
  const body = text.replace(/\r\n/g, '\n');
  if (path.endsWith('.json')) return JSON.stringify(canonical(JSON.parse(body)));
  return body
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/<!--[\s\S]*?-->/g, '')
    .replace(/(^|[^:"'`\\])\/\/[^\n]*/gm, '$1')
    .replace(/\s+/g, '')
    .replace(/'/g, '"')
    .replace(/;/g, '')
    .replace(/,([)\]}])/g, '$1');
}
