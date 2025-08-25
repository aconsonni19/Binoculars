import { error, fail, redirect } from '@sveltejs/kit';

const TAG = "[Binoculars]";

/** @type {import('./$types').Actions} */
export const actions = {
    default: async ({request, fetch}) => {
        // Gets the file from the form
        const formData = await request.formData()
        const file = formData.get("file");
    
        // Creates a new formData since the previous can't be transmitted again due to it being
        // tied to the form request
        const forwardFormData = new FormData();
        forwardFormData.append("file", file, file.name);


        const proxyResponse = await fetch("api/upload", {
            method: "POST",
            body: forwardFormData,
            credentials: "include"
        })

        if(proxyResponse.status === 422) { // The ELF file was invalid
            const { detail } = await proxyResponse.json();
            return fail(422, {error: detail});
        } else if (!proxyResponse.status === 201) { // There was some other error
            console.error(`${TAG} Something went wrong with the upload!`);
            return fail(response.status, {error: "Unexpected error!"});
        } 
        throw redirect(303, "/analysis")
    }    
};


