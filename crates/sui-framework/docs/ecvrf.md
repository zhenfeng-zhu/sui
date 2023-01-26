
<a name="0x2_ecvrf"></a>

# Module `0x2::ecvrf`



-  [Function `ecvrf_verify`](#0x2_ecvrf_ecvrf_verify)


<pre><code></code></pre>



<a name="0x2_ecvrf_ecvrf_verify"></a>

## Function `ecvrf_verify`



<pre><code><b>public</b> <b>fun</b> <a href="ecvrf.md#0x2_ecvrf_ecvrf_verify">ecvrf_verify</a>(proof: &<a href="">vector</a>&lt;u8&gt;, alpha_string: &<a href="">vector</a>&lt;u8&gt;, public_key: &<a href="">vector</a>&lt;u8&gt;, <a href="">hash</a>: &<a href="">vector</a>&lt;u8&gt;): bool
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b> <b>native</b> <b>fun</b> <a href="ecvrf.md#0x2_ecvrf_ecvrf_verify">ecvrf_verify</a>(proof: &<a href="">vector</a>&lt;u8&gt;, alpha_string: &<a href="">vector</a>&lt;u8&gt;, public_key: &<a href="">vector</a>&lt;u8&gt;, <a href="">hash</a>: &<a href="">vector</a>&lt;u8&gt;): bool;
</code></pre>



</details>
