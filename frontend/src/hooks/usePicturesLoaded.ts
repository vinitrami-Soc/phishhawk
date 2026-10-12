/* True once every picture has loaded; false while loading or if any is missing.
   The report pictures are optional: a build without them shows something else. */

import { useEffect, useState } from 'react';

export function usePicturesLoaded(sources: string[]) {
  const [loaded, setLoaded] = useState(false);
  const key = sources.join('|');
  useEffect(() => {
    let alive = true;
    Promise.all(
      sources.map(
        (src) =>
          new Promise<void>((resolve, reject) => {
            const img = new Image();
            img.onload = () => resolve();
            img.onerror = () => reject();
            img.src = src;
          }),
      ),
    ).then(
      () => alive && setLoaded(true),
      () => alive && setLoaded(false),
    );
    return () => {
      alive = false;
    };
  }, [key]);
  return loaded;
}
