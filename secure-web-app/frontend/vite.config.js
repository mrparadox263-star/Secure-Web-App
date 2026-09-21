import { defineConfig } from "vite";

export default defineConfig({
  server: {
    proxy: {
      "/auth": "http://127.0.0.1:5000",
      "/api": "http://127.0.0.1:5000",
    },
  },
});
