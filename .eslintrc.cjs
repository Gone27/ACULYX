'use strict';

/** @type {import('eslint').Linter.Config} */
module.exports = {
  root: true,
  parser: '@typescript-eslint/parser',
  parserOptions: {
    ecmaVersion: 2022,
    sourceType: 'module',
    project: './tsconfig.json',
    tsconfigRootDir: __dirname,
  },
  plugins: ['@typescript-eslint', 'no-unsanitized'],
  extends: [
    'eslint:recommended',
    'plugin:@typescript-eslint/recommended-type-checked',
  ],
  rules: {
    // ── Safety: untrusted string rendering ──────────────────────────────────
    // Ban innerHTML, outerHTML, insertAdjacentHTML with anything other than
    // a literal empty string. Use textContent or createElement instead.
    'no-unsanitized/property': 'error',
    'no-unsanitized/method': 'error',

    // ── Type safety ─────────────────────────────────────────────────────────
    '@typescript-eslint/no-explicit-any': 'error',
    '@typescript-eslint/no-non-null-assertion': 'warn',
    '@typescript-eslint/strict-boolean-expressions': 'error',

    // ── Unused code ─────────────────────────────────────────────────────────
    '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_' }],

    // ── Console — warn only (useful during development) ─────────────────────
    'no-console': 'warn',
  },
  ignorePatterns: ['dist/', 'node_modules/', '*.cjs', 'vite.config.ts'],
};
