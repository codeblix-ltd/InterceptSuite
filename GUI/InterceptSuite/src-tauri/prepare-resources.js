#!/usr/bin/env node

import { execSync } from 'child_process';
import path from 'path';
import os from 'os';
import { fileURLToPath } from 'url';

// Get __dirname equivalent in ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

/**
 * Cross-platform resource preparation script for Tauri builds
 * Detects the operating system and runs the appropriate script to copy native libraries
 */

function main() {
    const platform = os.platform();
    const buildConfig = process.argv[2] || 'Release';

    console.log(`Preparing resources for platform: ${platform}`);
    console.log(`Build configuration: ${buildConfig}`);

    try {
        if (platform === 'win32') {
            // Windows - run PowerShell script
            console.log('Running Windows resource preparation...');
            const psCommand = `pwsh -ExecutionPolicy Bypass -File "${path.join(__dirname, 'prepare-resources.ps1')}" -BuildConfig ${buildConfig}`;
            execSync(psCommand, { stdio: 'inherit', cwd: __dirname });
        } else {
            // Unix-like systems (Linux, macOS) - run bash script
            console.log('Running Unix resource preparation...');
            const shCommand = `bash "${path.join(__dirname, 'prepare-resources.sh')}" ${buildConfig}`;
            execSync(shCommand, { stdio: 'inherit', cwd: __dirname });
        }

        console.log('Resource preparation completed successfully!');
    } catch (error) {
        console.error('Error during resource preparation:', error.message);
        process.exit(1);
    }
}

main();



export { main };
