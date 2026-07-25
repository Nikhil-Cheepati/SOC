/**
 * Autonomous SOC MCP Server
 *
 * AI-powered Security Operations Center Tier-1 Analyst
 * and Incident Triage Agent.
 *
 * Features:
 * - Security alert analysis
 * - Threat intelligence lookup
 * - MITRE ATT&CK mapping
 * - IOC extraction
 * - Risk scoring
 * - Incident report generation
 */

import 'dotenv/config';

import { McpApplicationFactory } from '@nitrostack/core';

import { AppModule } from './app.module.js';



/**
 * Bootstrap the application
 */
async function bootstrap() {


    // Create and start the MCP server

    const server =
    await McpApplicationFactory.create(
        AppModule
    );


    await server.start();

}



// Start the application

bootstrap().catch((error) => {


    console.error(
        '❌ Failed to start SOC server:',
        error
    );


    process.exit(1);


});