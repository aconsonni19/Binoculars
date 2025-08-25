// TODO: Revaluate the need for the proxies

import { error, json } from "@sveltejs/kit";

export async function POST({ request }) {
    // Gets the file from the form
    const formData = await request.formData();
    const file = formData.get("file");

    // Creates a new formData since the previous can't be transmitted again due to it being
    // tied to the form request
    const forwardFormData = new FormData();
    forwardFormData.append("file", file, file.name);

    const backEndResponse = await fetch("http://localhost:5000/upload", {
        credentials: "include",
        method: "POST",
        body: forwardFormData
    });

    return new Response(backEndResponse.body, {
        status: backEndResponse.status,
        headers: backEndResponse.headers
    })
}
