import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

const apiTarget = process.env.VITE_API_TARGET || "http://127.0.0.1:8000";

// Preview tunnels must be named explicitly (both variables are read so the
// standard Vite convention and an explicit override work).
const allowedHosts = (
  process.env.VITE_ALLOWED_HOSTS ||
  process.env.__VITE_ADDITIONAL_SERVER_ALLOWED_HOSTS ||
  ""
)
  .split(",")
  .map((host) => host.trim())
  .filter(Boolean);

export default defineConfig({
  plugins: [react()],
  server: {
    host: "0.0.0.0",
    port: Number(process.env.PORT) || 3000,
    strictPort: true,
    allowedHosts,
    proxy: {
      "/api": {
        target: apiTarget,
        changeOrigin: true,
      },
    },
  },
  build: {
    outDir: "dist",
    sourcemap: false,
  },
});
