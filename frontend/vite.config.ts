import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

const backend = "http://127.0.0.1:8000";

// Development: the backend runs with --dev on 127.0.0.1:8000; open its one-time
// /_launch?token=... link on port 5173 instead. Proxying /api and /_launch keeps the
// session cookie on this origin, as in production.
// No changeOrigin: the backend checks Host (DNS rebinding) and Origin (CSRF), and
// --dev allow-lists exactly localhost:5173, so the browser's values must pass through.
export default defineConfig({
  plugins: [react()],
  server: {
    host: "localhost",
    port: 5173,
    strictPort: true,
    proxy: { "/api": backend, "/_launch": backend },
  },
  build: { outDir: "dist", sourcemap: false },
});
