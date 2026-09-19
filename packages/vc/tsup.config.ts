import { defineConfig } from 'tsup'

export default defineConfig({
  entry: ['src/index.ts', 'src/code.ts', 'src/schema/index.ts', 'cli/main.ts'],
  format: ['esm'],
  dts: true,
  clean: true,
  target: 'node20',
})
