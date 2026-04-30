import tailwindcss from "@tailwindcss/vite";
import vue from "@vitejs/plugin-vue";
import { defineConfig } from "vite";

export default defineConfig({
	plugins: [vue(), tailwindcss()],
	server: {
		port: 5173,
		proxy: {
			// Proxy /api/* to the Go yauth-go example server (port 3000
			// matches examples/admin and examples/vue/server).
			"/api": {
				target: "http://localhost:3000",
				changeOrigin: true,
			},
		},
	},
});
