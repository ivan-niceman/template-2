import { defineConfig } from 'astro/config';
import autoprefixer from 'autoprefixer';

export default defineConfig({
  base: '/',
  site: 'https://www.my-site.dev',
  vite: {
    css: {
      postcss: {
        plugins: [autoprefixer()],
      },
    },
  },
});
