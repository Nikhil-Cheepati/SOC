import { Injectable } from '@nitrostack/core';

import {
    THREAT_DATABASE,
    SECURITY_ALERTS,
    findThreat,
    type ThreatInfo,
    type SecurityAlert
} from './soc.data.js';



@Injectable()
export class SocService {



    /**
     * Get all security alerts
     */
    getAllAlerts(): SecurityAlert[] {

        return SECURITY_ALERTS;

    }





    /**
     * Find alert by ID
     */
    getAlertById(id:string): SecurityAlert | undefined {


        return SECURITY_ALERTS.find(
            alert => alert.id === id
        );

    }







    /**
     * Analyze security alert
     */
    analyzeAlert(alertText:string){


        let matchedThreat =
            THREAT_DATABASE.find(

                threat =>

                alertText
                .toLowerCase()
                .includes(
                    threat.name.toLowerCase()
                )

            );



        if(!matchedThreat){

            matchedThreat =
            findThreat(alertText);

        }



        return {


            alert:
            alertText,


            threat:
            matchedThreat || null,


            detected:
            matchedThreat
            ?
            true
            :
            false,


            message:

            matchedThreat

            ?

            "Threat identified successfully"

            :

            "No known threat detected"


        };


    }







    /**
     * MITRE ATT&CK lookup
     */
    getMitreTechnique(
        threatName:string
    ){


        const threat =
        findThreat(threatName);



        if(!threat){

            return {

                found:false,

                message:
                "MITRE technique not found"

            };

        }



        return {


            found:true,


            attack:
            threat.name,


            technique:
            threat.mitreTechnique,


            category:
            threat.category,


            severity:
            threat.severity


        };


    }








    /**
     * Calculate risk score
     */
    calculateRiskScore(

        severity:string,

        confidence:number

    ){


        let severityScore = 0;



        switch(severity.toUpperCase()){


            case "LOW":

                severityScore = 25;

                break;



            case "MEDIUM":

                severityScore = 50;

                break;



            case "HIGH":

                severityScore = 75;

                break;



            case "CRITICAL":

                severityScore = 100;

                break;


        }




        const risk = Math.round(

            severityScore * confidence

        );





        return {


            riskScore:
            risk,


            level:

            risk >= 80

            ?

            "CRITICAL"

            :

            risk >= 60

            ?

            "HIGH"

            :

            risk >= 30

            ?

            "MEDIUM"

            :

            "LOW"


        };


    }









    /**
     * Response recommendation
     */
    getResponseRecommendation(

        threatName:string

    ){



        const threat =
        findThreat(threatName);




        if(!threat){

            return [

                "Investigate manually"

            ];

        }





        return threat.recommendedActions;



    }









    /**
     * Generate SOC Incident Report
     */
    generateReport(

        attack:string,

        severity:string,

        risk:number

    ){



        const threat =
        findThreat(attack);




        return {


            reportTitle:

            "SOC Incident Report",



            attack:

            attack,



            severity:

            severity,



            riskScore:

            risk,



            mitreTechnique:

            threat

            ?

            threat.mitreTechnique

            :

            "Unknown",




            category:

            threat

            ?

            threat.category

            :

            "Unknown",




            description:

            threat

            ?

            threat.description

            :

            "No threat description available",




            indicators:

            threat

            ?

            threat.indicators

            :

            [],




            affectedSystems:

            threat

            ?

            threat.affectedSystems

            :

            [],




            recommendedActions:

            threat

            ?

            threat.recommendedActions

            :

            [

                "Perform manual investigation"

            ],




            generatedAt:

            new Date().toISOString()


        };


    }



}