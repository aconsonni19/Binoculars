//Controllo per caricare file .elf
document.getElementById('fileInput').addEventListener('change', function(event) {
    const file = event.target.files[0];
    if (file) {
        const fileName = file.name;
        if (!fileName.endsWith('.elf')) {
            alert('You can only upload files with .elf extension!');
        } else {
            window.location.href = 'https://github.com/aconsonni19/Binoculars'; //REINDIRIZZAMENTO PAGINA DI CONSO (FLASK)
        }
        event.target.value = ''; // Resetta il campo file
    }
});

//Funzione per il pulsante UPLOAD
document.getElementById('uploadButton').addEventListener('click', function() {
    document.getElementById('fileInput').click();
});

//Funzione per il pulsante ABOUT
document.getElementById('aboutButton').addEventListener('click', function() {
    window.location.href = '#about';
});

//Funzione per il pulsante GITHUB
document.getElementById('githubButton').addEventListener('click', function() {
    window.location.href = 'https://github.com/aconsonni19/Binoculars';
});