import { defineConfig } from 'tsup'

// Named entries give a flat dist/ where each .js sits next to its .d.ts.
const library = {
  index: 'src/index.ts',
  code: 'src/code.ts',
  formats: 'src/formats.ts',
  'schema/index': 'src/schema/index.ts',
}

export default defineConfig({
  entry: { ...library, 'cli/main': 'cli/main.ts' },
  format: ['esm'],
  // Declarations for the library only; the CLI is a program, not an API.
  dts: {
    entry: library,
    // tsup sets baseUrl for its declaration build, which TypeScript 6 reports as deprecated.
    compilerOptions: { ignoreDeprecations: '6.0' },
  },
  clean: true,
  target: 'node20',
})
