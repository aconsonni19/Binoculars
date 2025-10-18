<script>
    import Spinner from "./Spinner.svelte";
    let { isLoading, error, children } = $props()
    let message = "Loading...";

  </script>
  
{#if isLoading}
  <Spinner loadingMessage = {message}></Spinner>
{:else if error}
    <ErrorMessage message={error} />
{:else}
    {@render children()}
{/if}