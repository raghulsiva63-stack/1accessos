import { defineConfig, loadEnv } from "vite";
import { resolve } from "node:path";

export default defineConfig(({ mode }) => {
  const env = { ...loadEnv(mode, process.cwd(), "VITE_"), ...process.env };
  if (env.VITE_SUPABASE_URL !== "https://wkkmyacbhqloubtwvjom.supabase.co" || !env.VITE_SUPABASE_PUBLISHABLE_KEY?.startsWith("sb_publishable_")) {
    throw new Error("Production extension build requires the production Supabase URL and public publishable key.");
  }
  return {
  build: {
    outDir: "dist",
    emptyOutDir: true,
    rollupOptions: {
      input: {
        popup: resolve(import.meta.dirname, "popup.html"),
        warning: resolve(import.meta.dirname, "warning.html"),
        background: resolve(import.meta.dirname, "src/background.ts"),
        content: resolve(import.meta.dirname, "src/content.ts"),
      },
      output: {
        entryFileNames: "[name].js",
        chunkFileNames: "chunks/[name]-[hash].js",
        assetFileNames: "assets/[name]-[hash][extname]",
      },
    },
  },
  };
});
