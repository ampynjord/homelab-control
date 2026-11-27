import { defineConfig } from "vite";

// Tauri sert le dossier `dist` en production et ce serveur en developpement.
export default defineConfig({
  clearScreen: false,
  server: { port: 1420, strictPort: true, host: "127.0.0.1" },
  build: { target: "es2022", outDir: "dist", emptyOutDir: true },
});
