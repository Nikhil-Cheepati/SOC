export interface ThreatInfo {

    id: string;

    name: string;

    description: string;

    category: string;

    mitreTechnique: string;

    severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

    indicators: string[];

    affectedSystems: string[];

    detectionSource: string;

    recommendedActions: string[];

    active: boolean;

}


export const THREAT_DATABASE: ThreatInfo[] = [

    {
        id: 'ssh-brute-force',

        name: "SSH Brute Force Attack",

        description:
        "Attackers perform multiple SSH login attempts to gain unauthorized access by guessing credentials",

        category:
        "Credential Access",

        mitreTechnique:
        "T1110",

        severity:
        "HIGH",

        indicators: [
            "Multiple failed SSH login attempts",
            "Repeated authentication failures",
            "Suspicious external IP addresses"
        ],

        affectedSystems: [
            "Linux Servers",
            "SSH Services",
            "User Accounts"
        ],

        detectionSource:
        "Authentication Logs",

        recommendedActions: [
            "Block malicious IP",
            "Enable MFA",
            "Disable root login",
            "Monitor user activity"
        ],

        active:
        true,

    },


    {
        id: 'sql-injection',

        name: "SQL Injection Attack",

        description:
        "Attackers inject malicious SQL queries into application inputs to access or manipulate databases",

        category:
        "Initial Access",

        mitreTechnique:
        "T1190",

        severity:
        "CRITICAL",

        indicators: [
            "Suspicious SQL queries",
            "Database error messages",
            "Unexpected input parameters"
        ],

        affectedSystems: [
            "Web Applications",
            "Databases",
            "API Services"
        ],

        detectionSource:
        "Web Application Firewall Logs",

        recommendedActions: [
            "Validate user inputs",
            "Patch vulnerable applications",
            "Block malicious requests"
        ],

        active:
        true,

    },


    {
        id: 'malware-execution',

        name: "Malware Execution",

        description:
        "Execution of malicious programs on endpoints causing system compromise",

        category:
        "Execution",

        mitreTechnique:
        "T1204",

        severity:
        "HIGH",

        indicators: [
            "Unknown executable files",
            "Suspicious processes",
            "Abnormal system behaviour"
        ],

        affectedSystems: [
            "Endpoints",
            "Workstations",
            "Servers"
        ],

        detectionSource:
        "Endpoint Detection and Response",

        recommendedActions: [
            "Isolate infected device",
            "Perform malware analysis",
            "Remove malicious files"
        ],

        active:
        true,

    },


    {
        id: 'phishing',

        name: "Phishing Attack",

        description:
        "Attackers use fake emails and messages to steal credentials or deliver malware",

        category:
        "Initial Access",

        mitreTechnique:
        "T1566",

        severity:
        "HIGH",

        indicators: [
            "Suspicious email links",
            "Unknown attachments",
            "Fake login pages"
        ],

        affectedSystems: [
            "Email Accounts",
            "User Credentials",
            "Corporate Network"
        ],

        detectionSource:
        "Email Security Gateway",

        recommendedActions: [
            "Block malicious sender",
            "Reset compromised passwords",
            "Enable MFA"
        ],

        active:
        true,

    },


    {
        id: 'data-exfiltration',

        name: "Data Exfiltration",

        description:
        "Unauthorized transfer of sensitive information from organizational systems",

        category:
        "Exfiltration",

        mitreTechnique:
        "T1041",

        severity:
        "CRITICAL",

        indicators: [
            "Large outbound traffic",
            "Unknown external connections",
            "Sensitive file transfers"
        ],

        affectedSystems: [
            "File Servers",
            "Cloud Storage",
            "Databases"
        ],

        detectionSource:
        "Network Monitoring Tools",

        recommendedActions: [
            "Block suspicious connections",
            "Investigate affected systems",
            "Notify security team"
        ],

        active:
        true,

    }

];
export interface SecurityAlert {

    id:string;

    type:string;

    severity:
    "LOW" |
    "MEDIUM" |
    "HIGH" |
    "CRITICAL";

    sourceIP:string;

    description:string;

    timestamp:string;

    affectedAsset:string;

    status:
    "NEW" |
    "INVESTIGATING" |
    "RESOLVED";

}



export const SECURITY_ALERTS: SecurityAlert[] = [


{
    id:"ALERT001",

    type:"SSH Brute Force Attack",

    severity:"HIGH",

    sourceIP:"192.168.1.50",

    description:
    "200 failed SSH login attempts detected within 5 minutes",

    timestamp:
    "2026-07-25 10:30",

    affectedAsset:
    "Linux Server",

    status:
    "NEW"
},



{
    id:"ALERT002",

    type:"Malware Execution",

    severity:"CRITICAL",

    sourceIP:"10.0.0.15",

    description:
    "Suspicious executable detected on endpoint",

    timestamp:
    "2026-07-25 11:00",

    affectedAsset:
    "Employee Laptop",

    status:
    "NEW"
}


];
export function findThreat(type:string){

    return THREAT_DATABASE.find(
        threat =>
        threat.name
        .toLowerCase()
        .includes(
            type.toLowerCase()
        )
    );

}