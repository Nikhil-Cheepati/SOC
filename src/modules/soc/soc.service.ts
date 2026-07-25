import { Injectable } from '@nitrostack/core';

import { THREAT_DATABASE, type ThreatInfo }
from './soc.data.js';



@Injectable()

export class SocService {


    /**
     * Get all security threats
     */
    getAllThreats(): ThreatInfo[] {

        return THREAT_DATABASE;

    }



    /**
     * Get a specific threat by ID
     */
    getThreatById(id: string): ThreatInfo | undefined {

        return THREAT_DATABASE.find(
            threat => threat.id === id
        );

    }




    /**
     * Filter threats based on criteria
     */
    getThreatsFiltered(filters: {

        severity?: string;

        category?: string;

        active?: boolean;

        detectionSource?: string;

    }): ThreatInfo[] {


        let threats = [...THREAT_DATABASE];



        if(filters.severity) {

            threats = threats.filter(
                threat =>
                threat.severity.toLowerCase()
                === filters.severity!.toLowerCase()
            );

        }




        if(filters.category) {

            threats = threats.filter(
                threat =>
                threat.category
                .toLowerCase()
                .includes(
                    filters.category!.toLowerCase()
                )
            );

        }





        if(filters.active !== undefined) {

            threats = threats.filter(
                threat =>
                threat.active === filters.active
            );

        }





        if(filters.detectionSource) {

            threats = threats.filter(
                threat =>
                threat.detectionSource
                .toLowerCase()
                .includes(
                    filters.detectionSource!
                    .toLowerCase()
                )
            );

        }



        return threats;

    }







    /**
     * Get critical threats
     */
    getCriticalThreats(): ThreatInfo[] {


        return THREAT_DATABASE.filter(

            threat =>
            threat.severity === "CRITICAL"

        );


    }






    /**
     * Analyze a security alert log
     */
    analyzeAlert(log:string) {


        const data =
        log.toLowerCase();



        if(
            data.includes("failed login") ||
            data.includes("ssh") ||
            data.includes("brute")
        ){

            return {


                attack:
                "SSH Brute Force",


                severity:
                "HIGH",


                confidence:
                92,


                mitre:
                "T1110",


                recommendation:
                "Block IP address and enable MFA"


            };

        }





        if(
            data.includes("sql") ||
            data.includes("select")
        ){

            return {


                attack:
                "SQL Injection",


                severity:
                "CRITICAL",


                confidence:
                95,


                mitre:
                "T1190",


                recommendation:
                "Block malicious request and patch application"


            };

        }






        if(
            data.includes("malware") ||
            data.includes(".exe")
        ){

            return {


                attack:
                "Malware Execution",


                severity:
                "HIGH",


                confidence:
                90,


                mitre:
                "T1204",


                recommendation:
                "Isolate infected endpoint"


            };

        }





        return {


            attack:
            "Unknown Threat",


            severity:
            "LOW",


            confidence:
            50,


            mitre:
            "Unknown",


            recommendation:
            "Continue monitoring"


        };

    }







    /**
     * Calculate risk score
     */
    calculateRisk(
        severity:string,
        confidence:number
    ){


        let score =
        confidence;




        if(severity==="HIGH"){

            score +=10;

        }



        if(severity==="CRITICAL"){

            score +=20;

        }




        return {


            riskScore:
            Math.min(score,100),



            priority:

            score >= 90
            ?
            "CRITICAL"

            :

            score >= 70
            ?
            "HIGH"

            :

            "MEDIUM"


        };


    }







    /**
     * Generate incident report
     */
    generateReport(

        attack:string,

        severity:string,

        risk:number

    ){


        return {


            incidentID:
            "INC-" + Date.now(),


            attack,


            severity,


            riskScore:
            risk,


            status:
            "OPEN",



            actions:[

                "Collect security logs",

                "Investigate affected system",

                "Contain threat",

                "Document incident"

            ]


        };


    }


}