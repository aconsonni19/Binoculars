<script>
    import { Circle } from "svelte-loading-spinners";
    let { loadingMessage } = $props()
</script>
  
<div class="spinner-container">
    <Circle color = #ffa420 />
    <p>{loadingMessage}</p>
</div>