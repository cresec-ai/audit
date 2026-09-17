// @ts-check
import { defineConfig, globalIgnores } from 'eslint/config';
import js from '@eslint/js';
import tseslint from 'typescript-eslint';
import globals from 'globals';

// Flat ESLint config (ESLint 9 + typescript-eslint). Kept intentionally fast:
// this uses the *non-type-checked* recommended rule sets (no
// `parserOptions.project`/`projectService`), so `npm run lint` doesn't need a
// full TypeScript program build and stays quick enough for local + CI use on
// every push. Rule choices below favor catching real mistakes (unused
// imports/vars, unsafe equality, accidental `any`) over stylistic
// reformatting — there is no Prettier/formatting rule in here on purpose.
export default defineConfig([
  globalIgnores([
    'dist/**',
    'node_modules/**',
    'coverage/**',
    'demo-data/**',
    '.mcp-recorder/**',
    'docs/landing/**',
  ]),

  {
    files: [
      'src/**/*.ts',
      'test/**/*.ts',
      'demo/**/*.ts',
      'bench/**/*.ts',
      'receiver/**/*.ts',
      'eslint.config.js',
    ],
    extends: [js.configs.recommended, tseslint.configs.recommended],
    languageOptions: {
      ecmaVersion: 'latest',
      sourceType: 'module',
      globals: {
        ...globals.node,
      },
    },
    rules: {
      // Not part of either recommended set, zero findings in this codebase
      // today, and it catches a real class of bug (`==`/`!=` type coercion
      // surprises) for free.
      eqeqeq: ['error', 'always'],
    },
  },

  {
    // Tests deliberately use a few patterns that would be real smells in
    // src/: `x!` on values the test just asserted exist, and loosely-typed
    // fixtures/mocks. Recognize them as intentional here instead of
    // rewriting the suite to dodge the rules.
    files: ['test/**/*.ts'],
    rules: {
      '@typescript-eslint/no-non-null-assertion': 'off',
      '@typescript-eslint/no-explicit-any': 'warn',
      // `catch { /* fail-open */ }` is idiomatic in this codebase (see
      // src/**) for a swallow-and-continue guard; the default rule already
      // tolerates a comment-only catch body, this just documents the intent
      // and covers the same idiom if it appears bare in a test helper.
      'no-empty': ['error', { allowEmptyCatch: true }],
    },
  },
]);
