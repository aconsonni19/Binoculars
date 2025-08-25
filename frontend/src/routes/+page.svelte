<script>
    import { enhance } from "$app/forms";
    import main_image from "$lib/assets/main_image.png"

    let fileInput;
    let form;

    function openFilePicker() {
        fileInput.click();
    }

    function submitForm() {
        if(fileInput.files.length > 0) {
            form.submit();
        } else {
            alert("Please select a file!");
        }
    }
</script>

<div id = "content">
    <div id = "main_image_div">
        <img id = "main_image" src= {main_image} alt="Logo">
    </div>
    <p>Upload you binary to search for vulnerabilities!</p>
    <form id = "uploadForm" enctype="multipart/form-data" method="POST" use:enhance bind:this={form}>
		<button type="button" id="uploadButton" on:click={openFilePicker}>Upload</button>
		<input type="file" id="fileInput" name="file" style="display: none;" required bind:this={fileInput} accept=".elf" on:change={submitForm}>
	</form>
    <!--TODO: Consider a new page or a better way to do this-->
    <br><br><br><br><br><br><br><br><br><br><br><br><br><br>
    <div>
        <p id="about">
            <strong>Binoculars</strong> is an advanced web-based platform designed to streamline the security analysis of compiled binary files, specifically ELF (Executable and Linkable Format) binaries. Built for both seasoned professionals and curious newcomers, Binoculars transforms raw binaries into intelligible and actionable insights.
            <br><br>
            Through a seamless and intuitive interface, users can upload an ELF file and receive a comprehensive breakdown that includes:<br><br>
            - <strong>Disassembled Code</strong>: A low-level view of the binary, showing exact instructions executed by the processor.<br><br>
            - <strong>Decompiled Code</strong>: A higher-level reconstruction that helps users understand the logic and structure behind the compiled binary, even without access to the original source code.<br><br>
            - <strong>Vulnerability Detection</strong>: An automated scan highlights common security flaws such as buffer overflows, and more.
            <br><br>
            What sets Binoculars apart is its accessibility: users don't need to be reverse engineering experts or security researchers to gain meaningful insights. By abstracting the complexity of binary analysis, the tool empowers developers, auditors, and cybersecurity enthusiasts to explore, understand, and secure ELF binaries with confidence.
            <br><br>
            Whether you're auditing third-party software, analyzing malware, or learning about reverse engineering, Binoculars offers a safe, efficient, and powerful environment to explore compiled executables without the risk of executing untrusted code.
            <br><br>
            Our mission is to democratize binary analysis and vulnerability research, enabling everyone from developers to security analysts to contribute to safer software ecosystems.
        </p>
    </div>
</div>