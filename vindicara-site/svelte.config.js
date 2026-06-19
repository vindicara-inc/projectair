import adapter from '@sveltejs/adapter-node';
import { vitePreprocess } from '@sveltejs/vite-plugin-svelte';

/** Server-rendered Node app (ECS Fargate behind ALB). Public routes render full
 *  HTML per request (SSR, indexable); the Flightdeck console runs dynamic and
 *  real-time behind auth in the same app. One codebase, one domain. */
const config = {
  preprocess: vitePreprocess(),
  kit: {
    adapter: adapter(),
    alias: { $components: 'src/lib/components' }
  }
};
export default config;
