import { Injectable } from '@nitrostack/core';


import {

    THREAT_DATABASE,

    SECURITY_ALERTS,

    findThreat,

    type SecurityAlert

} from './soc.data.js';



import mitreData from '../../resources/mitre/enterprise-attack.json';





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
    getAlertById(
        id:string
    ): SecurityAlert | undefined {


        return SECURITY_ALERTS.find(

            alert =>
            alert.id === id

        );


    }









    /**
     * Analyze Security Alert
     */
    analyzeAlert(
        alertText:string
    ){



        let matchedThreat =

        THREAT_DATABASE.find(

            threat =>

            alertText
            .toLowerCase()
            .includes(

                threat.name
                .toLowerCase()

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
     * REAL MITRE ATT&CK DATASET LOOKUP
     */
    getMitreTechnique(

        attackName:string

    ){



        const objects:any[] =

        (mitreData as any).objects;






        const techniques =

        objects.filter(

            item =>


            item.type === "attack-pattern"

            &&


            item.name

            ?.toLowerCase()

            .includes(

                attackName
                .toLowerCase()

            )


        );








        if(
            techniques.length === 0
        ){


            return {


                found:false,


                message:

                "MITRE ATT&CK technique not found"



            };


        }








        return {


            found:true,



            count:

            techniques.length,



            techniques:


            techniques.map(

                tech => {


                    const mitreID =


                    tech.external_references

                    ?.find(

                        (ref:any)=>

                        ref.source_name ===
                        "mitre-attack"

                    )

                    ?.external_id;






                    return {


                        name:

                        tech.name,



                        id:

                        mitreID,



                        description:

                        tech.description
                        ?

                        tech.description

                        :

                        "No description available"


                    };


                }


            )


        };


    }









    /**
     * Calculate Risk Score
     */
    calculateRiskScore(

        severity:string,

        confidence:number

    ){



        let severityScore = 0;





        switch(
            severity.toUpperCase()
        ){


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






        const risk =

        Math.round(

            severityScore *
            confidence

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
     * Response Recommendation
     */
    getResponseRecommendation(

        threatName:string

    ){



        const threat =

        findThreat(

            threatName

        );






        if(!threat){


            return [

                "Perform manual investigation"

            ];


        }





        return threat.recommendedActions;



    }









    /**
     * Generate Incident Report
     */
    generateReport(


        attack:string,


        severity:string,


        risk:number


    ){





        const threat =

        findThreat(

            attack

        );




        const mitre =

        this.getMitreTechnique(

            attack

        );







        return {



            reportTitle:


            "Autonomous SOC Incident Report",





            generatedAt:


            new Date()
            .toISOString(),





            incident:


            {


                attack:


                attack,



                severity:


                severity,



                riskScore:


                risk



            },







            threatInformation:


            threat

            ?

            {


                category:

                threat.category,



                description:

                threat.description,



                indicators:

                threat.indicators,



                affectedSystems:

                threat.affectedSystems



            }



            :



            null,








            mitreMapping:


            mitre,








            recommendedActions:


            threat

            ?

            threat.recommendedActions


            :


            [


                "Investigate manually"


            ]



        };



    }







/**
 * MITRE Dataset Status
 */
getMitreDataCount(){


    const objects:any[] =
    (mitreData as any).objects;



    const techniques =
    objects.filter(

        item =>
        item.type === "attack-pattern"

    );



    return {


        dataset:
        "MITRE ATT&CK Enterprise",


        version:
        "19.1",


        totalObjects:
        objects.length,


        attackTechniques:
        techniques.length,


        status:
        "Loaded Successfully"


    };


}
}