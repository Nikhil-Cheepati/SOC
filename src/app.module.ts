import { McpApp, Module, ConfigModule } from '@nitrostack/core';

import { SocModule } from './modules/soc/soc.module.js';



/**
 * Root Application Module
 *
 * Autonomous SOC Tier-1 Analyst
 * and Incident Triage Agent
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

        SocModule

    ],

})


export class AppModule {}