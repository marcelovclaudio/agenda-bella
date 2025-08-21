/* eslint-disable */
const fs = require('fs');

const configs = ['base.json', 'nextjs.json', 'vite.json', 'express.json'];

configs.forEach((config) => {
  try {
    const content = fs.readFileSync(config, 'utf8');
    const ts = JSON.parse(content);

    if (!ts.compilerOptions) {
      console.error('✗', config, 'missing compilerOptions');
      process.exit(1);
    }

    console.log('✓', config, 'valid TypeScript config');
  } catch (e) {
    console.error('✗', config, e.message);
    process.exit(1);
  }
});

console.log('All TypeScript configurations are valid!');
