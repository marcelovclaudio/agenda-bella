import tseslint from 'typescript-eslint';
import rootConfig from '../../eslint.config.js';

export default tseslint.config(...rootConfig, {
  files: ['**/*.ts', '**/*.tsx'],
  languageOptions: {
    parserOptions: {
      project: './tsconfig.json',
      tsconfigRootDir: import.meta.dirname,
    },
  },
  rules: {
    // UI-specific rules
    'react/prop-types': 'off',
    '@typescript-eslint/no-explicit-any': 'warn',
  },
});
