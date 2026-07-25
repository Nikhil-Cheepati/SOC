import {
    ToolDecorator as Tool,
    ExecutionContext,
    Injectable,
    z
} from '@nitrostack/core';


import { SocService } from './soc.service.js';



// =================================
// INPUT SCHEMAS
// =================================


const AnalyzeAlertSchema = z.object({

    log: z
        .string()
        .describe(
            "Security log or alert details"
        )

});



const ThreatIntelSchema = z.object({

    ip: z
        .string()
        .describe(
            "IP address to check"
        )

});



const MitreSchema = z.object({

    attack: z
        .string()
        .describe(
            "Attack name for MITRE lookup"
        )

});



const RiskSchema = z.object({

    severity: z
        .string()
        .describe(
            "Threat severity level"
        ),


    confidence: z
        .number()
        .describe(
            "Detection confidence score"
        )

});



const ResponseSchema = z.object({

    attack: z
        .string()
        .describe(
            "Detected attack type"
        )

});



const CorrelationSchema = z.object({

    events:
    z.array(z.string())
    .describe(
        "List of security events"
    )

});



const ReportSchema = z.object({

    attack:
    z.string(),

    severity:
    z.string(),

    risk:
    z.number()

});




// =================================
// SOC TOOL CLASS
// =================================


@Injectable({
    deps: [SocService]
})


export class SocTools {


    constructor(

        private readonly socService: SocService

    ){}




    // =================================
    // TOOL 1
    // ANALYZE SECURITY ALERT
    // =================================


    @Tool({

        name:
        "analyze_security_alert",

        description:
        "Analyze security logs and detect cyber attacks",

        inputSchema:
        AnalyzeAlertSchema

    })


    async analyzeSecurityAlert(

        args:
        z.infer<typeof AnalyzeAlertSchema>,

        ctx: ExecutionContext

    ){


        ctx.logger.info(
            "Analyzing security alert"
        );


        return this.socService.analyzeAlert(
            args.log
        );


    }







    // =================================
    // TOOL 2
    // THREAT INTELLIGENCE
    // =================================


    @Tool({

        name:
        "check_threat_intelligence",

        description:
        "Check whether an IP address is malicious",

        inputSchema:
        ThreatIntelSchema

    })


    async checkThreatIntelligence(

        args:
        z.infer<typeof ThreatIntelSchema>,

        ctx: ExecutionContext

    ){


        ctx.logger.info(
            "Checking threat intelligence"
        );


        return {


            ip:
            args.ip,


            status:
            "Suspicious",


            riskScore:
            85,


            reports:
            27


        };


    }







    // =================================
    // TOOL 3
    // MITRE ATT&CK LOOKUP
    // =================================


    @Tool({

        name:
        "mitre_attack_lookup",

        description:
        "Map attack to MITRE ATT&CK technique",

        inputSchema:
        MitreSchema

    })


    async mitreAttackLookup(

        args:
        z.infer<typeof MitreSchema>

    ){


        return {


            attack:
            args.attack,


            technique:
            "T1110",


            tactic:
            "Credential Access",


            description:
            "MITRE ATT&CK technique information"


        };


    }








    // =================================
    // TOOL 4
    // IOC EXTRACTION
    // =================================


    @Tool({

        name:
        "extract_iocs",

        description:
        "Extract indicators of compromise from logs",

        inputSchema:
        AnalyzeAlertSchema

    })


    async extractIOCs(

        args:
        z.infer<typeof AnalyzeAlertSchema>

    ){


        const ipRegex =
        /\b\d{1,3}(\.\d{1,3}){3}\b/g;



        return {


            ips:

            args.log.match(ipRegex)
            ||
            [],



            keywords:


            [

                "malware",

                "phishing",

                "exploit"

            ]


            .filter(

                item =>

                args.log
                .toLowerCase()
                .includes(item)

            )


        };


    }








    // =================================
    // TOOL 5
    // RISK CALCULATION
    // =================================


    @Tool({

        name:
        "calculate_risk_score",

        description:
        "Calculate security risk score",

        inputSchema:
        RiskSchema

    })


    async calculateRiskScore(

        args:
        z.infer<typeof RiskSchema>

    ){


        return this.socService.calculateRisk(

            args.severity,

            args.confidence

        );


    }








    // =================================
    // TOOL 6
    // RESPONSE RECOMMENDATION
    // =================================


    @Tool({

        name:
        "response_recommendation",

        description:
        "Recommend incident response actions",

        inputSchema:
        ResponseSchema

    })


    async responseRecommendation(

        args:
        z.infer<typeof ResponseSchema>

    ){


        return {


            attack:
            args.attack,


            actions:


            [

                "Block malicious IP",

                "Collect additional logs",

                "Reset compromised credentials",

                "Enable MFA",

                "Investigate affected systems"

            ]


        };


    }








    // =================================
    // TOOL 7
    // LOG CORRELATION
    // =================================


    @Tool({

        name:
        "log_correlation_analysis",

        description:
        "Correlate multiple security events",

        inputSchema:
        CorrelationSchema

    })


    async logCorrelation(

        args:
        z.infer<typeof CorrelationSchema>

    ){


        const threatScore =
        args.events.length * 30;



        return {


            events:
            args.events,


            finding:
            "Multiple events indicate coordinated attack",


            threatLevel:


            threatScore >= 90

            ?

            "CRITICAL"

            :

            "HIGH"


        };


    }








    // =================================
    // TOOL 8
    // INCIDENT REPORT
    // =================================


    @Tool({

        name:
        "generate_incident_report",

        description:
        "Generate SOC incident report",

        inputSchema:
        ReportSchema

    })


    async generateIncidentReport(

        args:
        z.infer<typeof ReportSchema>

    ){


        return this.socService.generateReport(

            args.attack,

            args.severity,

            args.risk

        );


    }



}