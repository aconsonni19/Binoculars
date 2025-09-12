<script>
    // TODO: Rivedere e refactorare bene questa parte di codice
    import {Pane, Splitpanes} from "svelte-splitpanes";
    import { navigating  } from "$app/state";
    import { Circle, Jumper } from "svelte-loading-spinners"
    import { onMount } from "svelte";
    import { getData, sendData } from "./utils.js"
    import { error } from "@sveltejs/kit";
    import hijs from "highlight.js/lib/core";
    import c from "highlight.js/lib/languages/c"
    import "highlight.js/styles/a11y-dark.css"
    import { enhance } from "$app/forms";

    hijs.registerLanguage("c", c)


    let form;
    
    let isDisassembling = true;
    let isDecompiling = true;

    const tag = "[Binoculars]:"

    let disassembly = null;
    let highLightedLines = [];

    let disassemblyError = null;
    let decompileError = null;

    let selectedAnalysis = "";
    let analysesResult = null;
    let analysesError = null;

    let cmdInputsLengths = [];
    let cmdInputsNumber = 0;

    let isAnalyzing = false;


    $: {
        if(cmdInputsNumber != cmdInputsLengths.length && cmdInputsNumber != null) {
            cmdInputsLengths = Array(cmdInputsNumber).fill(0);
        }
    }

    onMount(async () => {
        getData("/api/disassemble", ( { data }) => {
            disassembly = data;
            isDisassembling = false;
        }, ({ error }) => {
            disassemblyError = error.message;
        });

        getData("/api/decompile", ( { data }) => {
            let lineNumber = 1;

            for(const func of data) {
                const highlited = hijs.highlight(func.code, { language: "c"}).value;
                const lines = highlited.split("\n");

                for(const line of lines) {
                    highLightedLines.push({ number: lineNumber++, html: line});
                }

            }
            isDecompiling = false;
        }, ({ error }) => {
            decompileError = error.message;
        })
    });


    function handleFormSubmission(event) {
        event.preventDefault();

        isAnalyzing = true;
        analysesResult = null;

        const formData = new FormData(form);

        sendData("/api/analyses/vulndetect", formData, ( {data} )  => {
            isAnalyzing = false;
            analysesResult = data;
        }, ({ error }) => {
            analysesError = error.message;
        });
    }

</script>

<Splitpanes vertical theme = "theme">
    <Pane size = {33}>
        <h3>Disassembled code</h3>

        {#if isDisassembling}
            <div class = "spinner-container">
                <Circle color = "#ffa420"/>
                <p>Disassembling...</p>
            </div>
        {:else if disassemblyError}
            <p>{disassemblyError}</p>
        {:else}
            <table id = "disassembled_table">
                <thead>
                    <tr>
                        <th>Address</th>
                        <th>Operation</th>
                        <th>Operands</th>
                    </tr>
                </thead>
                <tbody>
                    {#each disassembly.disassembly as section}
                        <!-- Section header -->
                        <tr class = "section-header">
                            <td colspan="3">{section.section}</td>
                        </tr>

                        <!-- Section code-->
                        {#each section.instructions as instr}
                            <tr>
                                <td>{instr.address}</td>
                                <td class = "mnemonic mnemonic-{instr.mnemonic}">{instr.mnemonic}</td>
                                <td>{instr.op_str}</td>
                            </tr>
                        {/each}                        
                    {/each}
                </tbody>
            </table>
        {/if}
    </Pane>
    <Pane size = {33}>
        <h3>Decompiled code</h3>
        {#if isDecompiling}
            <div class = "spinner-container">
                <Circle color = "#ffa420" />
                <p>Decompiling...</p>
            </div>
        {:else if decompileError}
            <p>{decompileError}</p>
        {:else}
            <table id = "decompiled_table">
                <thead>
                    <tr>
                        <th>Line</th>
                        <th>Code</th>
                    </tr>
                </thead>
                <tbody>
                    {#each highLightedLines as line}
                        <tr>
                            <td>{line.number}</td>
                            <td class = "code-line">{@html line.html}</td>
                        </tr>
                    {/each}
                </tbody>
            </table>
        {/if}
    </Pane>
    <Pane size = {33}>
        <h3>Vulnerability analyses</h3>
        {#if selectedAnalysis == ""}
            <select bind:value={selectedAnalysis} id = "select_analysis" onsubmit="{(e) => e.preventDefault()}">
                <option value = "" selected disabled style="display: none;">Choose one of the available analysis!</option>
                <option value = "VulnDetect">VulnDetect</option>
                <option value = "Arbiter">Arbiter</option>
            </select>
        {:else if selectedAnalysis == "VulnDetect"}
            <form method="POST" id="vuln_analysis_form" action="?/vulnDetect" use:enhance bind:this={form}>
                <!-- Length of stdin -->
                <label for="stdin_length">Length of stdin input</label>
                <input type="number" id="stdin_length" name="stdin_input_length" min="0" required><br>
            
                <!-- Number of command-line parameters -->
                <label for="param_count">Number of CMD parameters</label>
                <input type="number" id="param_count" name="param_count" min="0" required defaultValue = "0" bind:value={cmdInputsNumber} placeholder="0"><br>
            
                <div id = "param_fields">
                    {#each cmdInputsNumber != null ? Array(cmdInputsNumber) : Array(0) as _, i}
                        <label for = "param_input_{i+1}">Parameter {i+1} length</label>
                        <input id = "param_input_{i+1}" type="number" min = "0" required bind:value={cmdInputsLengths[i]}>
                    {/each}
                </div>
                <input type="hidden" id = "param_lengths" name = "param_lengths" value="{JSON.stringify(cmdInputsLengths)}"/>
                <!-- Submit button -->
                <button type="button" onclick="{handleFormSubmission}">Start analysis!</button>
                <button onclick="{selectedAnalysis = ""}">Go back</button>
            </form>
            {#if isAnalyzing}
                <div id = "analysis-spinner">
                    <Circle color = "#ffa420" />
                    <p>Analyzing with VulnDetect...</p>
                </div>
            {/if}
            {#if analysesResult}
                <table class = "analysis_result">
                    <thead>
                        <tr>
                            <th>Address</th>
                            <th>Description</th>
                            <th>Vulnerability</th>
                        </tr>
                    </thead>

                    <tbody>
                        {#each Object.entries(analysesResult) as [address, vuln]}
                            <tr>
                                <td>{address}</td>
                                <td>{vuln.Description}</td>
                                <td>{vuln.Vulnerability_found}</td> 
                            </tr>
                            
                        {/each}
                    </tbody>
                </table>
            {:else if analysesError}
                <p>:(</p>
            {/if}
        {/if}
    </Pane>
</Splitpanes>