import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// In development the Vite server proxies /api to the FastAPI backend so the
// session cookie stays same-origin, exactly as in production.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: { "/api": "http://127.0.0.1:8000" },
  },
  build: { outDir: "dist", sourcemap: false },
});
