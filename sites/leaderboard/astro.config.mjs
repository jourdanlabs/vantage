import { defineConfig } from 'astro/config';

export default defineConfig({
  site: 'https://benchmark.vantage.dev',
  output: 'static',
  build: {
    assets: '_assets',
  },
});
