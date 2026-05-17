import { sveltekit } from '@sveltejs/kit/vite';
import tailwindcss from '@tailwindcss/vite';
import { defineConfig } from 'vite';

export default defineConfig({
	plugins: [tailwindcss(), sveltekit()],
	build: {
		// Split heavy third-party deps into their own chunks so the initial
		// client bundle stays under the dashboard's hard budget (350KB initial,
		// 700KB total — see scripts/check-bundle.mjs).
		rollupOptions: {
			output: {
				manualChunks: (id) => {
					if (id.includes('node_modules/three/')) return 'three';
					if (id.includes('node_modules/@noble/')) return 'noble';
					return undefined;
				}
			}
		},
		chunkSizeWarningLimit: 400
	}
});
