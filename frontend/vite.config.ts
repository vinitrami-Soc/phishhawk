import tailwindcss from '@tailwindcss/vite';
import react from '@vitejs/plugin-react';
import { fileURLToPath, URL } from 'node:url';
import { defineConfig, type Plugin } from 'vite';

/* Development only. The mock API (src/mocks/) answers fetch() calls, but the
   report <iframe> and the download links are ordinary page requests that go to
   the dev server. Answer them with a placeholder, sandboxed like the real files,
   so the preview shows where the report goes instead of a nested copy of the app.
   On the PhishHawk server these URLs return the real files. */
function previewFiles(): Plugin {
  const page =
    '<!doctype html><meta charset="utf-8"><title>Preview</title>' +
    '<p>Preview only. On the PhishHawk server this frame shows the full HTML report.</p>';
  return {
    name: 'phishhawk-preview-files',
    apply: 'serve',
    configureServer(server) {
      server.middlewares.use((req, res, next) => {
        const url = req.url ?? '';
        if (!/^\/api\/v1\/(analyses\/\d+\/files\/[^/?]+|messages\/\d+\/raw)(\?|$)/.test(url)) return next();
        res.setHeader('Content-Security-Policy', "default-src 'none'; sandbox");
        res.setHeader('X-Content-Type-Options', 'nosniff');
        res.setHeader('Cache-Control', 'no-store');
        if (url.includes('download=1') || url.includes('/raw')) {
          res.setHeader('Content-Type', 'text/plain; charset=utf-8');
          res.setHeader('Content-Disposition', 'attachment; filename="phishhawk-preview-placeholder.txt"');
          res.end('Preview only. On the PhishHawk server this link downloads the real file.\n');
          return;
        }
        res.setHeader('Content-Type', 'text/html; charset=utf-8');
        res.end(page);
      });
    },
  };
}

// PhishHawk serves the built app under /app/ (PHISHHAWK_FRONTEND_DIR). The dev
// server, and so the AI Studio preview, runs at the site root, so the base is
// only set for the build. In code, build public URLs with import.meta.env.BASE_URL.
export default defineConfig(({ command }) => ({
  base: command === 'build' ? '/app/' : '/',
  plugins: [react(), tailwindcss(), previewFiles()],
  resolve: { alias: { '@': fileURLToPath(new URL('./src', import.meta.url)) } },
  server: {
    // HMR is disabled in AI Studio via DISABLE_HMR env var.
    hmr: process.env.DISABLE_HMR !== 'true',
    watch: process.env.DISABLE_HMR === 'true' ? null : {},
  },
  // No data: URIs: the server's CSP allows fonts only from 'self'.
  build: { assetsInlineLimit: 0 },
}));
