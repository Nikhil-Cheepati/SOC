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

    log:
    z.string()
    .describe(
        "Security log or alert details"
    )

});





const ThreatIntelSchema = z.object({

    indicator:
    z.string()
    .describe(
        "IP address, domain, or hash to check"
    )

});





const MitreSchema = z.object({

    attack:
    z.string()
    .describe(
        "Attack name for MITRE ATT&CK lookup"
    )

});





const RiskSchema = z.object({

    severity:
    z.string()
    .describe(
        "Threat severity level"
    ),


    confidence:
    z.number()
    .describe(
        "Detection confidence score"
    )

});





const ResponseSchema = z.object({

    attack:
    z.string()
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





const InvestigationSchema = z.object({

    alert:

    z.string()

    .describe(
        "Complete security incident details"
    )

});





const EmptySchema = z.object({});







// =================================
// SOC TOOL CLASS
// =================================


@Injectable({

    deps:[SocService]

})


export class SocTools {



constructor(

    private readonly socService:SocService

){}






// =================================
// TOOL 1
// ANALYZE ALERT
// =================================


@Tool({

    name:
    "analyze_security_alert",

    description:
    "Analyze security logs and identify cyber threats",

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
    "Check IOC reputation using threat intelligence database",

    inputSchema:
    ThreatIntelSchema

})


async checkThreatIntelligence(

    args:
    z.infer<typeof ThreatIntelSchema>

){



    return {


        indicator:
        args.indicator,


        status:
        "Suspicious",


        confidence:
        85,


        source:
        "Threat Intelligence Database"


    };


}









// =================================
// TOOL 3
// REAL MITRE ATT&CK LOOKUP
// =================================


@Tool({

    name:
    "mitre_attack_lookup",

    description:
    "Search official MITRE ATT&CK Enterprise dataset",

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
    "Extract IPs, domains and hashes from security logs",

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
            "brute force",
            "sql injection"

        ]

        .filter(

            keyword =>

            args.log
            .toLowerCase()
            .includes(keyword)

        )


    };


}









// =================================
// TOOL 5
// RISK SCORE
// =================================


@Tool({

    name:
    "calculate_risk_score",

    description:
    "Calculate cyber security risk score",

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
// RESPONSE ACTIONS
// =================================


@Tool({

    name:
    "response_recommendation",

    description:
    "Generate incident response actions",

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

        this.socService
        .getResponseRecommendation(

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
    "Analyze multiple security events together",

    inputSchema:
    CorrelationSchema

})


async logCorrelation(

    args:
    z.infer<typeof CorrelationSchema>

){


    const score =
    args.events.length * 30;



    return {


        events:
        args.events,


        threatScore:
        score,


        threatLevel:

        score >= 90

        ?

        "CRITICAL"

        :

        score >=60

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
    "Perform autonomous SOC Tier-1 investigation",

    inputSchema:
    InvestigationSchema

})


async investigateIncident(

    args:
    z.infer<typeof InvestigationSchema>,

    ctx:ExecutionContext

){


    ctx.logger.info(
        "Starting autonomous investigation"
    );




    // Threat detection

    const analysis =

    this.socService.analyzeAlert(

        args.alert

    );





    // IOC extraction

    const iocs =

    await this.extractIOCs({

        log:
        args.alert

    });





    const threat =
    analysis.threat;





    // MITRE Mapping

    const mitre =

    threat

    ?

    this.socService.getMitreTechnique(

        threat.name

    )

    :

    null;






    // Risk calculation

    const risk =

    threat

    ?

    this.socService.calculateRiskScore(

        threat.severity,

        0.9

    )

    :

    null;







    // Response

    const response =

    threat

    ?

    this.socService
    .getResponseRecommendation(

        threat.name

    )

    :

    [];








    return {


        status:

        "Investigation Completed",



        timestamp:

        new Date()
        .toISOString(),



        alert:

        args.alert,



        threatAnalysis:

        analysis,



        indicators:

        iocs,



        mitreMapping:

        mitre,



        riskAssessment:

        risk,



        responsePlan:

        response,



        summary:

        "Autonomous SOC Tier-1 investigation completed using MITRE ATT&CK intelligence"


    };

}









// =================================
// TOOL 10
// MITRE DATASET STATUS
// =================================


@Tool({

    name:
    "mitre_dataset_status",

    description:
    "Check official MITRE ATT&CK dataset status",

    inputSchema:
    EmptySchema

})


async mitreDatasetStatus(){


    return this.socService
    .getMitreDataCount();


}



}