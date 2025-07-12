function initResizable(resizer, leftPane, rightPane) {
    let startX;
    let startLeftWidth;
    let startRightWidth;

    resizer.addEventListener("mousedown", (e) => {
        e.preventDefault();
        startX = e.clientX;
        startLeftWidth = leftPane.offsetWidth;
        startRightWidth = rightPane.offsetWidth;

        // Aggiungi una classe per indicare che il resizer è attivo
        resizer.classList.add("active");

        function onMouseMove(e) {
            const dx = e.clientX - startX;

            // Calcola la nuova larghezza per il pannello sinistro e destro
            const newLeftWidth = startLeftWidth + dx;
            const newRightWidth = startRightWidth - dx;

            // Imposta limiti minimi per evitare che i pannelli diventino troppo piccoli
            const minWidth = 150; // Larghezza minima per entrambi i pannelli

            if (newLeftWidth > minWidth && newRightWidth > minWidth) {
                leftPane.style.width = `${newLeftWidth}px`;
                rightPane.style.width = `${newRightWidth}px`;
            }
        }

        function onMouseUp() {
            // Rimuovi gli event listener quando il mouse viene rilasciato
            document.removeEventListener("mousemove", onMouseMove);
            document.removeEventListener("mouseup", onMouseUp);

            // Rimuovi la classe attiva
            resizer.classList.remove("active");
        }

        // Aggiungi gli event listener per il movimento e il rilascio del mouse
        document.addEventListener("mousemove", onMouseMove);
        document.addEventListener("mouseup", onMouseUp);
    });
}

window.addEventListener("DOMContentLoaded", () => {
    const left = document.querySelector(".left");
    const center = document.querySelector(".center");
    const right = document.querySelector(".right");

    const resizerLeft = document.getElementById("resizer-left");
    const resizerRight = document.getElementById("resizer-right");

    // Inizializza i resizer con i pannelli adiacenti
    initResizable(resizerLeft, left, center);
    initResizable(resizerRight, center, right);
});

//Funzione per il pulsante GITHUB
document.getElementById('githubButton').addEventListener('click', function() {
    window.location.href = 'https://github.com/aconsonni19/Binoculars';
});

document.getElementById('exitButton').addEventListener('click', function() {
    window.location.href = '/';
});

document.getElementById("param_count").addEventListener("input", function () {
    const paramFields = document.getElementById("paramFields");

    // Cleare previous fields
    while(paramFields.firstChild) {
        paramFields.removeChild(paramFields.firstChild)
    }


    const count = parseInt(this.value);
    for (let i = 0; i < count; i++) {
        const label = document.createElement("label");
        label.htmlFor = `param${i}`;
        label.textContent = `Length of parameter ${i + 1}:`;

        const input = document.createElement("input");
        input.type = "number";
        input.id = `param${i}`;
        input.name = `param${i}`;
        input.min = "0";
        input.required = true;

        paramFields.appendChild(label);
        paramFields.appendChild(input);
        paramFields.appendChild(document.createElement("br"));
    }
});





document.getElementById("analysis_form").addEventListener("submit", function(e) {
    e.preventDefault() // Prevent page reload

    // Hide the form when the analysis starts
    document.getElementById("analysis_form").style.display = "none";

    const vulnContent = document.getElementById("vuln_content");


    // Make the loading spinner visible
    spinner = document.getElementById("spinner")
    spinner.classList.add("visible");

    const stdinInputLen = parseInt(document.getElementById("stdin_length").value, 10);
    const paramCount = parseInt(document.getElementById("param_count").value, 10);

    const paramsLengths = []
    for(i = 0; i < paramCount; i++) {
        const param_value = parseInt(document.getElementById(`param${i}`)?.value, 10);
        if(param_value)
            paramsLengths.push(param_value)
    }

    fetch("/analysis/VulnDetect", {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({stdinInputLen, paramCount, paramsLengths})
    })
    .then(res => res.json())
    .then(data => {
        
        if(Object.keys(data).length == 0) {
            const noVulnParagraph = document.createElement("p")
            noVulnParagraph.innerText = "No vulnerabilities found!"
            vulnContent.appendChild(noVulnParagraph)
        } else {
            const vulnTable = document.createElement("table")
                
            const row = document.createElement("tr")

            const addressHeader = document.createElement("th")
            addressHeader.innerText = "Address"
            row.appendChild(addressHeader)

            const typeHeader = document.createElement("th")
            typeHeader.innerText = "Type"
            row.appendChild(typeHeader)

            const descriptionHeader = document.createElement("th")
            descriptionHeader.innerText = "Description"
            row.appendChild(descriptionHeader)

            vulnTable.appendChild(row)

            for (const [addr, info] of Object.entries(data.results || {})) {
                const row = document.createElement("tr");
            
                const addrCell = document.createElement("td");
                addrCell.innerText = `${addr}`;
                row.appendChild(addrCell);
            
                const vulnCell = document.createElement("td");
                vulnCell.innerText = `${info.Vulnerability_found}`;
                row.appendChild(vulnCell);
            
                const descriptionCell = document.createElement("td");
                descriptionCell.innerText = `${info.Description}`;
                row.appendChild(descriptionCell);
            
                vulnTable.appendChild(row);
            }
            spinner.classList.remove("visible")
            vulnContent.appendChild(vulnTable)
        }
    })
    .catch(error => {
        spinner.classList.remove("visibile");
        vulnContent.innerText = `Error during analysis: ${error}`
    })
})


