<script>
    import { Pane, Splitpanes } from "svelte-splitpanes";
    import { navigating } from "$app/state";
    import { onMount } from "svelte";
    import { decompileStore, disassemblyStore, vulnDetectAnalysisStore } from "./stores.js";
    import { getData, highlightCodeLines } from "./utils";
    import hijs from "highlight.js/lib/core";
    import c from "highlight.js/lib/languages/c"
    import "highlight.js/styles/a11y-dark.css"
    import { enhance } from "$app/forms";
    import AsyncContainer from "./components/AsyncContainer.svelte";
    import VulnDetectForm from "./components/VulnDetectForm.svelte";
    import { error } from "@sveltejs/kit";
    import ArbiterForm from "./components/ArbiterForm.svelte";
    hijs.registerLanguage("c", c)

    function fetchData() {
        getData("/api/disassemble",
            ( {data} ) => {
                disassemblyState.disassembly = data.disassembly;
                disassemblyState.isLoading = false;
            }, ( {error} ) => {
                disassemblyState.error = error.message;
                disassemblyState.isLoading = false;
            }
        );
        getData("/api/decompile",
            ( {data} ) => {
                decompileState.decompile = highlightCodeLines(data, hijs);
                decompileState.isLoading = false;
            }, ( {error} ) => {
                decompileState.error = error.message;
                disassemblyState.isLoading = false;
            }
        );
    }

    let selectedAnalysis = ""

    let disassemblyState = {
        disassembly: null,
        error: null,
        isLoading: true
    };

    let decompileState = {
        decompile: null,
        error: null,
        isLoading: true
    };

    let vulnDetectAnalysisState = {
        results: null,
        error: null,
        isLoading: false,
        cmdInputsLength: [],
        cmdInputsNumber: 0
    }



    onMount(async () => {
        fetchData();
    });

</script>


<Splitpanes vertical theme = "theme">
    <Pane size = {33}>
        <h3>Disassembled code</h3>
        <AsyncContainer isLoading={disassemblyState.isLoading} error={disassemblyState.error}>
            <table id = "disassembled_table">
                <thead>
                    <tr>
                        <th>Address</th>
                        <th>Operation</th>
                        <th>Operands</th>
                    </tr>
                </thead>
                <tbody>
                    {#each disassemblyState.disassembly as section}
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
        </AsyncContainer>
    </Pane>
    <Pane size={33}>
        <h3>Decompiled code</h3>
        <AsyncContainer isLoading={decompileState.isLoading} error={decompileState.error}>
            <table id="decompiled_table">
                <thead>
                    <tr>
                        <th>Line</th>
                    </tr>
                </thead>
                <tbody>
                    {#each  decompileState.decompile as line}
                        <tr>
                        <td>{line.number}</td>
                        <td class="code-line">{@html line.html}</td>
                        </tr>
                    {/each}
                </tbody>
            </table>
        </AsyncContainer>
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
            <VulnDetectForm 
            bind:selectedAnalysis = {selectedAnalysis}>
            </VulnDetectForm>
        {:else if selectedAnalysis == "Arbiter"}
            <ArbiterForm
            bind:selectedAnalysis = {selectedAnalysis}
            ></ArbiterForm>
        {/if}
    </Pane>
</Splitpanes>