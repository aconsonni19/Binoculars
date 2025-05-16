/*function initResizable(resizer, targetPane, isLeft) {
    let startX;
    let startWidth;

    resizer.addEventListener("mousedown", (e) => {
        e.preventDefault();
        startX = e.clientX;
        startWidth = targetPane.offsetWidth;

        // Add the active class
        resizer.classList.add("active");

        function onMouseMove(e) {
            const dx = e.clientX - startX;
            let newWidth;

            if (isLeft) {
                newWidth = startWidth + dx;
            } else {
                newWidth = startWidth - dx;
            }

            if (newWidth > 100 && newWidth < window.innerWidth - 100) {
                targetPane.style.width = `${newWidth}px`;
            }
        }

        function onMouseUp() {
            document.removeEventListener("mousemove", onMouseMove);
            document.removeEventListener("mouseup", onMouseUp);

            // Remove the active class
            resizer.classList.remove("active");
        }

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

    initResizable(resizerLeft, left, true);
    initResizable(resizerRight, right, false);
});*/

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

//Funzione per il pulsante ABOUT
document.getElementById('aboutButton').addEventListener('click', function() {
    window.location.href = '#about'; //DA SISTEMARE (FLASK)
});

//Funzione per il pulsante GITHUB
document.getElementById('githubButton').addEventListener('click', function() {
    window.location.href = 'https://github.com/aconsonni19/Binoculars';
});