function initResizable(resizer, targetPane, isLeft) {
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
});