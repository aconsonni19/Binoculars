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
        cmdInputsLengths: [],
        cmdInputsNumber: 0
    }

    function handleFormSubmission(event) {
        event.preventDefault()

        analysisState.isLoading = true;
    
        const formData = new FormData(form);
        sendData("/api/analyses/vulndetect", formData, 
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

<form method="POST" id="vuln_analysis_form" action="?/vulnDetect" use:enhance bind:this={form}>
    <!-- Length of stdin -->
    <label for="stdin_length">Length of stdin input</label>
    <input type="number" id="stdin_length" name="stdin_input_length" min="0" required><br>

    <!-- Number of command-line parameters -->
    <label for="param_count">Number of CMD parameters</label>
    <input type="number" id="param_count" name="param_count" min="0" required defaultValue = "0" bind:value={analysisState.cmdInputsNumber} placeholder="0"><br>

    <div id = "param_fields">
        {#each analysisState.cmdInputsNumber != null ? Array(analysisState.cmdInputsNumber) : Array(0) as _, i}
            <label for = "param_input_{i+1}">Parameter {i+1} length</label>
            <input id = "param_input_{i+1}" type="number" min = "0" required bind:value={analysisState.cmdInputsLengths[i]}>
        {/each}
    </div>
    <input type="hidden" id = "param_lengths" name = "param_lengths" value="{JSON.stringify(analysisState.cmdInputsLengths)}"/>
    <!-- Submit button -->
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
                <th>Address</th>
                <th>Description</th>
                <th>Vulnerability</th>
            </tr>
        </thead>

        <tbody>
            {#each Object.entries(analysisState.results) as [address, vuln]}
                <tr>
                    <td>{address}</td>
                    <td>{vuln.Description}</td>
                    <td>{vuln.Vulnerability_found}</td> 
                </tr>
                
            {/each}
        </tbody>
    </table>
{:else if analysisState.error}
    <ErrorMessage message = {analysisState.error.message}></ErrorMessage>
{/if}