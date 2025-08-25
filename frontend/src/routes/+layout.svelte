<script>
	import favicon from '$lib/assets/favicon.png';
	import navbar_logo from "$lib/assets/navbar_logo.png"
	import "../style.css"
	let { children } = $props();
</script>

<svelte:head>
	<link rel="icon" href={favicon} />
</svelte:head>

<nav class = "navbar">
	<a href = "/"><img src = {navbar_logo} alt = "Logo" id = "navbar_logo"></a>
	<div id = "buttons">
		<a href = "/#about">About</a>
		<a href = "https://github.com/aconsonni19/Binoculars">Github</a>
	</div>
</nav>

{@render children?.()}
