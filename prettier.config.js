/** @type {import("prettier").Config} */
export default {
  // Base formatting
  semi: true,
  singleQuote: true,
  tabWidth: 2,
  trailingComma: 'es5',
  printWidth: 100,

  // Plugin configurations
  plugins: ['@ianvs/prettier-plugin-sort-imports', 'prettier-plugin-tailwindcss'],

  // Sort imports configuration
  importOrder: ['^(react|react-dom)$', '^next', '^@agenda-bella/(.*)$', '^[./]'],

  // Tailwind plugin (automatically sorts classes)
  tailwindFunctions: ['clsx', 'cn', 'cva'],
};
