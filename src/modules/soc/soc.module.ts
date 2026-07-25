import { Module } from '@nitrostack/core';

import { SocService } from './soc.service.js';

import { SocTools } from './soc.tools.js';



@Module({

    name: 'soc',

    description:
    'Autonomous SOC Tier-1 Analyst and Incident Triage Agent',


    controllers: [

        SocTools

    ],


    providers: [

        SocService

    ],

})


export class SocModule {}