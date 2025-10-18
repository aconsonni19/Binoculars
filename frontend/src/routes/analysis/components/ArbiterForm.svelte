<script>
    import { enhance } from "$app/forms";
    import { error } from "@sveltejs/kit";
    import { sendData } from "../utils";    
    import Spinner from "./Spinner.svelte";
    import ErrorMessage from "./ErrorMessage.svelte";
    let form;


    export let selectedAnalysis

    let analysisState = {
        results: null,
        error: null,
        isLoading: false,
    }

    function handleFormSubmission(event) {
        event.preventDefault()

        analysisState.isLoading = true;
    
        const formData = new FormData(form);
        sendData("/api/analyses/arbiter", formData, 
            ( {data} ) => {
                analysisState.results = data;
                analysisState.isLoading = false

                console.log(analysisState.results)


            }, ( {error} ) => {
                analysisState.error = error.message;
                analysisState.isLoading = false;
            }
        );
    }
</script>



<form method="POST" id="vuln_analysis_form" action="?/arbiter" use:enhance bind:this={form}> 
    <button type="button" on:click= {handleFormSubmission}>Start analysis!</button>
    <button type="button" on:click = {() => selectedAnalysis = ""}>Go back</button>
</form>


{#if analysisState.isLoading}
    <Spinner loadingMessage = {"Analyzing..."}></Spinner>
{:else if analysisState.results}
    <br>
    <table class = "analysis_result">
        <thead>
            <tr>
                <th>Vulnerability</th>
                <th>Result</th>
            </tr>
        </thead>

        <tbody>
            {#each Object.entries(analysisState.results) as [CWE, result]}
                <tr>
                    <td>{CWE}</td>
                    <td>{result}</td>
                </tr>            
            {/each}
        </tbody>
    </table>
{:else if analysisState.error}
    <ErrorMessage message = {analysisState.error.message}></ErrorMessage>
{/if}




