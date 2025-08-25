import { error, json } from "@sveltejs/kit";
// TODO: Maybe look into a way to make an universal proxy instead of using multiple routes and files
export async function POST({ request }) {

    const backEndResponse = await fetch("http://localhost:5000/analyses/vulndetect", {
        method: "POST",
        headers: request.headers,
        body: request.body,
        credentials: "include",
        duplex: "half"
    });
    return new Response(backEndResponse.body, {
        status: backEndResponse.status,
        headers: backEndResponse.headers
    });
}