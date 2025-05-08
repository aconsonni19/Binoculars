
document.getElementById("uploadButton").addEventListener("click", () => {
    document.getElementById("fileInput").click();  // Open file picker
});

document.getElementById("fileInput").addEventListener("change", () => {
    // Check if a file is selected
    if (document.getElementById("fileInput").files.length > 0) {
        document.getElementById("uploadForm").submit();  // Submit the form
    } else {
        alert("Please select a file.");
    }
});

//Funzione per il pulsante ABOUT
document.getElementById('aboutButton').addEventListener('click', function() {
    window.location.href = '#about';
});

//Funzione per il pulsante GITHUB
document.getElementById('githubButton').addEventListener('click', function() {
    window.location.href = 'https://github.com/aconsonni19/Binoculars';
});