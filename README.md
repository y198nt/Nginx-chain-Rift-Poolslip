# nginx PoolSlip × Rift — ASLR-independent RCE chain

First public chain of two recently-disclosed nginx rewrite-engine bugs into a single
**ASLR-independent remote `system()`** on the **stock official `nginx:1.30.0`** Docker image
(Debian 13, glibc 2.41) — **no hardcoded addresses, no nginx restart, ~90 % per fresh worker.**

* **CVE-2026-9256 "PoolSlip"** — an `$args` heap over-read → leaks live **libc + heap**.
* **CVE-2026-42945 "rift"** — an `is_args` heap overflow (URL-safe bytes only) → a **2-byte partial
  overwrite** of a `limit_conn` cleanup pointer → `ngx_destroy_pool` walks it → `system(cmd)`.

Both are the *same* `is_args` two-pass mismatch pointed at two sinks. Full technical write-up: [Writeup](https://hackmd.io/@y198/S1xoJVxWzl)


---

> ## Disclosure & safety
> * Both CVEs are **already patched** and **under active exploitation in the wild**. **Upgrade to
>   nginx 1.30.2 (stable) or 1.31.1 (mainline)** — note `1.30.1` fixes rift but is *still* vulnerable
>   to PoolSlip, so only `1.30.2` closes both. NGINX Plus: R36 P5 / R32 P7 / R37.0.1.1.
> * This is published for **education and authorized testing only**. It runs against the **bundled
>   local Docker lab** — do **not** point it at infrastructure you don't own or have written
>   permission to test.

| CVE | nickname | vulnerable | fixed (nginx OSS) |
|---|---|---|---|
| CVE-2026-42945 | rift     | 0.6.27 – 1.30.0          | 1.30.1 / 1.31.0 |
| CVE-2026-9256  | PoolSlip | 0.1.17 – 1.30.1 + 1.31.0 | **1.30.2** / 1.31.1 |

---

## What's in the repo

| File | Purpose |
|---|---|
| `nginx.conf` | A credible API-gateway config (the *target* — `limit_conn`, a v1→v2 migration rewrite, an upload proxy, a degraded search page). **No allocator tuning.** |
| `run.sh` | Stands up the local lab: stock `nginx:1.30.0` serving `nginx.conf`, plus a slow upstream, on host `:19322`. |
| `exp_official.py` | The full chain: PoolSlip leak → derive libc/heap → spray → groom → rift partial overwrite → `system()`. |

## Requirements

* Docker, Python 3 (to run `exp_official.py`), `curl`, Linux x86-64.
* The lab is **fully self-contained / offline** — `run.sh` uses `perl` (already in the stock nginx image) for the slow upstream, so there's no extra package, no `slow_backend` file, and no internet needed. The nginx binary itself stays stock.
* *Optional:* to follow the gdb sessions in `WRITEUP.md`, `docker exec` in and `apt-get install gdb file binutils`, then load gef.

## Run it

```bash
git clone https://github.com/y198nt/Nginx-chain-Rift-Poolslip
cd Nginx-chain-Rift-Poolslip

bash run.sh                                          # stock nginx:1.30.0 on http://127.0.0.1:19322
python3 exp_official.py --cmd 'id > /tmp/rce_proof'  # leak → overwrite → system()
docker exec nginx-rift-official cat /tmp/rce_proof   # → uid=101(nginx) ...
```

`exp_official.py` is **one-shot** (~90 % per fresh worker): it leaks once and fires once. If the
proof file is empty, the groom landed a slot off — just re-run it.

```
docker rm -f nginx-rift-official      # tear the lab down
```

## How it works (short)

1. **Leak (PoolSlip).** A `rewrite ^/search/((.*))$ /lookup?$1$2` makes the copy pass set
   `r->args.len` *past* the buffer; the degraded `/search` page reflects `$args` into adjacent heap.
   After a short warm-up, a **libpcre-cluster pointer** (fixed `0xb0ad08` below libc) and a heap
   pointer settle at stable offsets → `libc_base` and `heap_base`, nothing hardcoded.
2. **Write (rift).** The rift overflow can only emit **URL-safe bytes**, so a full 48-bit address is
   writable ~0.9 % of the time under ASLR. Instead we overwrite just the **low 2 bytes** of an
   *already-valid* `limit_conn` cleanup pointer — the ASLR-random high bytes ride along untouched →
   **ASLR-independent**.
3. **Fire.** The pointer is redirected into a sprayed `ngx_pool_cleanup_t{handler=&system,
   data=cmd, next=0}`; closing the victim triggers `ngx_destroy_pool`'s cleanup walk →
   `system(cmd)`.

See [Writeup](https://hackmd.io/@y198/S1xoJVxWzl) for the full derivation, gdb sessions, and the dead-ends/pivots.

## Mitigations & detection

* **Patch** (upgrade to 1.30.2 / 1.31.1) — the only real fix.
* The write only fires through a `rewrite` whose replacement contains `?` **and** references a PCRE
  capture (`$1`/`$2`), or a nested-capture pattern like `^/x/((.*))$ → /y?$1$2`. Audit configs for
  those and rework the offending `rewrite`/`set` until patched.
* A **reflected `$args`** (or any request-derived variable echoed back) is what turns the over-read
  into an info-leak — don't reflect request args verbatim.
* WAF / log signals: `%2B`/`+` floods in the URI path (`GET /search/+++…`), `503`s from a degraded
  page echoing a long `$args`, and worker `SIGSEGV`/respawn storms.

## Credits & references

* Original component PoCs: [DepthFirstDisclosures/Nginx-Rift](https://github.com/DepthFirstDisclosures/Nginx-Rift) (rift).
* Vendor advisories — CVE-2026-42945 (rift) and CVE-2026-9256 (PoolSlip), F5/nginx.
* Chaining, ASLR-independent technique, and Debian glibc-2.41 port: this repo.
