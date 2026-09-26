// @ts-check
import tseslint from 'typescript-eslint';
import noUnsanitized from 'eslint-plugin-no-unsanitized';

export default tseslint.config(
  // ── Files to lint ───────────────────────────────────────────────────────────
  {
    files: ['src/**/*.ts', 'src/**/*.tsx', 'tests/**/*.ts'],
  },

  // ── Base recommended rules ───────────────────────────────────────────────────
  ...tseslint.configs.recommendedTypeChecked,

  // ── TypeScript parser options ────────────────────────────────────────────────
  {
    languageOptions: {
      parserOptions: {
        projectService: true,
        tsconfigRootDir: import.meta.dirname,
      },
    },
  },

  // ── Custom rules ─────────────────────────────────────────────────────────────
  {
    plugins: {
      'no-unsanitized': noUnsanitized,
    },
    rules: {
      // ── Safety: untrusted string rendering ────────────────────────────────
      // Ban innerHTML, outerHTML, insertAdjacentHTML with attacker-controlled
      // values. Always use textContent or createElement instead.
      'no-unsanitized/property': 'error',
      'no-unsanitized/method': 'error',

      // ── Type safety ───────────────────────────────────────────────────────
      '@typescript-eslint/no-explicit-any': 'error',
      '@typescript-eslint/no-non-null-assertion': 'warn',
      '@typescript-eslint/strict-boolean-expressions': 'error',

      // ── Unused code ───────────────────────────────────────────────────────
      '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_' }],

      // ── Console ───────────────────────────────────────────────────────────
      'no-console': 'warn',
    },
  },

  // ── Ignores ──────────────────────────────────────────────────────────────────
  {
    ignores: ['dist/**', 'node_modules/**', 'vite.config.ts', 'playwright.config.ts'],
  },
);
