import js from '@eslint/js';
import tseslint from 'typescript-eslint';
import globals from 'globals';

export default tseslint.config(
  { ignores: ['dist/**', 'node_modules/**', 'coverage/**'] },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    languageOptions: {
      globals: { ...globals.browser, ...globals.node, chrome: 'readonly' },
    },
    rules: {
      '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_', varsIgnorePattern: '^_' }],
      'no-console': ['warn', { allow: ['warn', 'error', 'info'] }],
      eqeqeq: ['error', 'always'],
      'no-eval': 'error',
      'no-implied-eval': 'error',
      'no-new-func': 'error',
    },
  },
  {
    // The extension UI must never render untrusted strings as HTML.
    files: ['src/extension/**/*.ts'],
    rules: {
      'no-restricted-properties': [
        'error',
        { property: 'innerHTML', message: 'Use textContent / the el() helper; never render untrusted HTML.' },
        { property: 'outerHTML', message: 'Never render untrusted HTML.' },
      ],
      'no-restricted-syntax': [
        'error',
        { selector: "CallExpression[callee.property.name='insertAdjacentHTML']", message: 'Never render untrusted HTML.' },
      ],
    },
  },
);
