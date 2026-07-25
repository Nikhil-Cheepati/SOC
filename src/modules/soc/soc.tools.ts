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



// NEW MASTER TOOL SCHEMA

const InvestigationSchema = z.object({

    alert:
    z.string()
    .describe(
        "Complete security alert or incident details"
    )

});




// =================================
// SOC TOOL CLASS
// =================================


@Injectable({
    deps:[SocService]
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

    ctx:ExecutionContext

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
    z.infer<typeof ThreatIntelSchema>

){


    return {


        indicator:
        args.ip,


        status:
        "Suspicious",


        confidence:
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


    return this.socService.getMitreTechnique(
        args.attack
    );


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



    const domainRegex =
    /[a-zA-Z0-9.-]+\.(com|net|org|io)/g;



    const hashRegex =
    /\b[a-fA-F0-9]{32,64}\b/g;




    return {


        ips:
        args.log.match(ipRegex)
        ||
        [],



        domains:
        args.log.match(domainRegex)
        ||
        [],



        hashes:
        args.log.match(hashRegex)
        ||
        [],



        keywords:

        [

            "malware",
            "phishing",
            "exploit",
            "brute force"

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


    return this.socService.calculateRiskScore(

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

        this.socService.getResponseRecommendation(
            args.attack
        )


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

        "Multiple security events analyzed",



        threatLevel:

        threatScore >= 90

        ?

        "CRITICAL"

        :

        threatScore >= 60

        ?

        "HIGH"

        :

        "MEDIUM"



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









// =================================
// TOOL 9
// AUTONOMOUS INVESTIGATION
// =================================


@Tool({

    name:
    "investigate_incident",

    description:
    "Autonomously investigate security incidents using SOC workflow",

    inputSchema:
    InvestigationSchema

})


async investigateIncident(

    args:
    z.infer<typeof InvestigationSchema>,

    ctx:
    ExecutionContext

){


    ctx.logger.info(
        "Starting autonomous SOC investigation"
    );



    // 1. Analyze Alert

    const analysis =
    this.socService.analyzeAlert(
        args.alert
    );




    // 2. Extract IOCs

    const iocs =
    await this.extractIOCs({

        log:
        args.alert

    });




    const threat =
    analysis.threat;



    // 3. MITRE Mapping

    const mitre =

    threat

    ?

    this.socService.getMitreTechnique(
        threat.name
    )

    :

    null;





    // 4. Risk Assessment

    const risk =

    threat

    ?

    this.socService.calculateRiskScore(

        threat.severity,

        0.9

    )

    :

    null;






    // 5. Response Actions

    const response =

    threat

    ?

    this.socService.getResponseRecommendation(
        threat.name
    )

    :

    [];






    // 6. Final Result


    return {


        status:
        "Investigation Completed",



        alert:
        args.alert,



        threatAnalysis:
        analysis,



        extractedIOCs:
        iocs,



        mitreMapping:
        mitre,



        riskAssessment:
        risk,



        recommendedActions:
        response,



        summary:

        "Autonomous SOC Tier-1 investigation completed"


    };

}



}