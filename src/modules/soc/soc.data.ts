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