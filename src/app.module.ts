import { McpApp, Module, ConfigModule } from '@nitrostack/core';

import { PizzazModule } from './modules/pizzaz/pizzaz.module.js';

import { SocModule } from './modules/soc/soc.module.js';



/**
 * Root Application Module
 * 
 * Autonomous SOC Tier-1 Analyst & Incident Triage Agent
 */
@McpApp({

    module: AppModule,

    server: {

        name: 'autonomous-soc-agent',

        version: '1.0.0'

    },

    logging: {

        level: 'info'

    }

})


@Module({

    name: 'soc',

    description:
    'Autonomous SOC Tier-1 Analyst and Incident Triage Agent',


    imports: [

        ConfigModule.forRoot(),

        PizzazModule,

        SocModule

    ],

})


export class AppModule {}