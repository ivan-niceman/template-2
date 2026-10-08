import { defineConfig } from 'astro/config';
import autoprefixer from 'autoprefixer';
import vercel from '@astrojs/vercel';

export default defineConfig({
  base: '/',
  site: 'https://www.my-site.dev',
  output: 'server',
  adapter: vercel(),
  vite: {
    css: {
      postcss: {
        plugins: [autoprefixer()],
      },
    },
  },
});
