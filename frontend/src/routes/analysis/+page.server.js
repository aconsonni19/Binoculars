import { form } from "$app/server";
import { error, fail } from "@sveltejs/kit";

const TAG = "[Binoculars]:";


export const actions = {
    vulnDetect: async ({request, fetch}) => {
        const formData = await request.formData()

        body = {
            stdin_input_length: formData.get("stdin_input_length"),
            param_lengths: formData.get("") 
        }



        const proxyResponse = await fetch("/api/analyses/vulndetect", {
            method: "POST", 
            body: formData,
            credentials: "include"
        });
    },
    arbiter: async ({ request, fetch}) => {
        
    }
}
