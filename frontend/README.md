# PhishHawk web app frontend

The browser app the PhishHawk server serves at `/app/`, built in Google AI
Studio from [docs/FRONTEND-BRIEF.md](../docs/FRONTEND-BRIEF.md). React 18,
Vite and Tailwind CSS; every file is bundled, so it runs under the server's
strict Content-Security-Policy. The Docker image builds it in; see
[docs/FRONTEND.md](../docs/FRONTEND.md).

```bash
npm ci --ignore-scripts   # dependencies from package-lock.json
npm test                  # the build brief's rules, the locked files, routes, the mock API
npx tsc --noEmit          # types
npm run build             # dist/, served by `PHISHHAWK_FRONTEND_DIR=frontend/dist phishhawk server run`
npm run dev               # a preview at http://localhost:3000 with a mock API (development only)
```

Third-party code and its licences: [licenses/](licenses/).
