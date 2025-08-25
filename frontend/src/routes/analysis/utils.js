
const TAG = "[Binoculars]:";

// TODO: Dare una pulita a questo codice!

export async function getData(endpoint, handleResultsFunction, handleErrorFunction) {
    let error = null;
    let data = null;
    try{
        const response = await fetch(endpoint, {
            method: "GET",
            credentials: "include"
        });
        data = await response.json();
        return handleResultsFunction({ data });
    } catch(e) {
        console.error(`${TAG} Something went wrong!`, e)
        return handleErrorFunction( { error });
    }
}

export async function sendData(endpoint, body, handleResultsFunction, handleErrorFunction) {
    let error = null;
    let data = null;

    try {
        const response = await fetch(endpoint, {
            method: "POST",
            body: body,
            credentials: "include"
        });
        data = await response.json();
        return handleResultsFunction({ data });
    } catch(e) {
        console.error(`${TAG} Something went wrong!`, e);
        return handleErrorFunction({ error });
    }
}

