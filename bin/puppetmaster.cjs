# Rename to .cjs extension
mv bin/puppetmaster.js bin/puppetmaster.cjs

# Update contents (CommonJS compatible)
cat > bin/puppetmaster.cjs << 'EOF'
#!/usr/bin/env node
'use strict';

const { join } = require('path');
const { Command } = require('commander');
const program = new Command();

// Error handling for module loading
const loadModule = (path) => {
  try {
    require(path);
  } catch (err) {
    console.error(`❌ Failed to load ${path}:`, err.message);
    process.exit(1);
  }
};

program
  .version('1.0.0')
  .description('Puppetmaster MITM Monitoring Suite');

program
  .command('scan')
  .description('Start MITM traffic monitoring')
  .action(() => loadModule(join(__dirname, '../scanner/index.cjs')));

program
  .command('logs')
  .description('View real-time traffic logs')
  .action(() => loadModule(join(__dirname, '../scanner/logwatcher.cjs')));

program.parse(process.argv);
EOF
