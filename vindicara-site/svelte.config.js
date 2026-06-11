import adapter from '@sveltejs/adapter-static';
import { vitePreprocess } from '@sveltejs/vite-plugin-svelte';

/** Static SPA for S3/CloudFront, same as the current vindicara.io deploy. */
const config = {
  preprocess: vitePreprocess(),
  kit: {
    adapter: adapter({ fallback: '404.html', strict: false }),
    alias: { $components: 'src/lib/components' }
  }
};
export default config;
