function initResizable(resizer, targetPane, isLeft) {
    let startX;
    let startWidth;

    resizer.addEventListener("mousedown", (e) => {
        e.preventDefault();
        startX = e.clientX;
        startWidth = targetPane.offsetWidth;

        function onMouseMove(e) {
            const dx = e.clientX - startX;
            let newWidth;

            if (isLeft) {
                // Left pane: grows/shrinks by moving the resizer to the right
                newWidth = startWidth + dx;
            } else {
                // Right pane: grows if you drag to the left shrinks if you drag right
                newWidth = startWidth -dx;
            }

            // Constrains the panel to a minimum width
            if (newWidth > 100 && newWidth < window.innerWidth - 100) {
                targetPane.style.width = `${newWidth}px`;
            }
        }

        function onMouseUp() {
            document.removeEventListener("mousemove", onMouseMove);
            document.removeEventListener("mouseup", onMouseUp);
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