package handshake.node.server;

/**
 * All static content served by WebAdminServer, embedded directly as
 * Java string constants rather than packaged as separate resource
 * files -- deliberately, per design decision: loose HTML/CSS/JS files
 * sitting next to the jar are files an operator could accidentally
 * edit or corrupt, whereas content baked into the compiled class can't
 * be altered without rebuilding the project itself.
 *
 * This first version is intentionally minimal: just enough to prove
 * the server correctly serves all three content types with the right
 * headers. Config read/write and the hsd-style event/socket channels
 * are deliberately NOT part of this first step -- planned as separate,
 * later additions once this basic serving mechanism is confirmed
 * working.
 */
public final class WebAdminServerContent {

    private WebAdminServerContent() {}

    public static final String INDEX_HTML = """
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <title>Easy Handshake Node</title>
                <link rel="stylesheet" href="/style.css">
            </head>
            <body>
                <header>
                    <h1>Easy Handshake Node</h1>
                    <p class="subtitle">Local admin interface &middot; v<span id="version">...</span></p>
                </header>
                <div id="halt-banner" style="display:none; background:#7a1f1f; color:#fff; padding:12px 20px; font-weight:bold;">
                    Node halted -- Urkel tree root mismatch at height <span id="halt-height"></span>.
                    This needs investigation or recovery before sync can safely resume.
                </div>
                <main>
                    <div class="column">
                        <section class="card">
                            <h2>Node Status</h2>
                            <p>Uptime: <span id="uptime">Loading...</span></p>
                            <p>Block Height: <span id="block-height">Loading...</span></p>
                            <p>Sync Progress: <span id="sync-percent">Loading...</span></p>
                            <p>Chain Database: <span id="db-size">Loading...</span></p>
                        </section>

                        <section class="card">
                            <h2>API Key</h2>
                            <p class="hint">Required for RPC calls made from anywhere other than this machine.</p>
                            <code id="api-key">Loading...</code>
                        </section>

                        <section class="card">
                            <h2>Mempool</h2>
                            <p>Transactions: <span id="mempool-count">Loading...</span></p>
                            <p>Size: <span id="mempool-bytes">Loading...</span></p>
                            <p>Min relay fee: <span id="mempool-fee">Loading...</span></p>
                        </section>

                        <section class="card danger-zone">
                            <h2>Danger zone</h2>
                            <button id="stop-node-btn">Stop node</button>
                            <p id="stop-message"></p>
                        </section>
                    </div>

                    <div class="column">
                        <section class="card">
                            <h2>Peers</h2>
                            <p id="peers-summary" class="hint">Loading...</p>
                            <div class="peer-scroll">
                            <table id="peertable">
                                <thead>
                                    <tr><th>Peer</th><th>Status</th><th>Score</th></tr>
                                </thead>
                                <tbody><tr><td colspan="3">Loading...</td></tr></tbody>
                            </table>
                            </div>
                        </section>
                    </div>

                    <div class="column">
                        <section class="card">
                            <h2>RPC Operations</h2>
                            <p class="hint">Changes to the RPC host require a restart to take effect.</p>
                            <form id="config-form">
                                <label>
                                    RPC host
                                    <input type="text" name="rpc.host">
                                </label>
                                <button type="submit">Save</button>
                            </form>
                            <p id="config-message"></p>
                            <p class="hint">Test any RPC method directly, without a separate terminal or curl command.</p>
                            <label>
                                Method
                                <select id="rpc-method-select"></select>
                            </label>
                            <form id="rpc-form"></form>
                            <button id="rpc-submit-btn" type="submit" form="rpc-form">Submit</button>
                        </section>

                        <section class="card">
                            <h2>RPC Output</h2>
                            <pre id="rpc-output">(no call made yet)</pre>
                        </section>
                    </div>
                </main>
                <script src="/app.js"></script>
            </body>
            </html>
            """;

    public static final String STYLE_CSS = """
            :root {
                color-scheme: light;
                --accent: #c9975a;
                --accent-light: #edc79a;
                --accent-dark: #b6793c;
                --copper: #db9082;
                --border: #e0dddb;
                --bg: #fdfdfd;
                --surface: #f5f2ef;
                --text-heading: #19191a;
                --text-body: #55565c;
                --text-muted: #6e6e74;
            }
            body {
                font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
                max-width: 1500px;
                margin: 2rem auto;
                padding: 0 1rem;
                line-height: 1.5;
                background: var(--bg);
                color: var(--text-body);
            }
            header {
                margin-bottom: 2rem;
            }
            h1 {
                margin-bottom: 0.25rem;
                color: var(--text-heading);
            }
            .subtitle {
                color: var(--text-muted);
                margin-top: 0;
            }
            main {
                display: grid;
                grid-template-columns: repeat(3, 1fr);
                gap: 1.5rem;
                align-items: start;
            }
            .column {
                display: flex;
                flex-direction: column;
                gap: 1rem;
            }
            @media (max-width: 1000px) {
                main {
                    grid-template-columns: repeat(2, 1fr);
                }
                .column:nth-child(3) {
                    grid-column: span 2;
                }
            }
            @media (max-width: 700px) {
                main {
                    grid-template-columns: 1fr;
                }
                .column:nth-child(3) {
                    grid-column: span 1;
                }
            }
            .card {
                background: var(--surface);
                border: 1px solid var(--border);
                border-radius: 8px;
                padding: 1rem 1.5rem;
                margin-bottom: 1rem;
                break-inside: avoid;
                -webkit-column-break-inside: avoid;
                page-break-inside: avoid;
            }
            .card h2 {
                margin-top: 0;
                font-size: 1.1rem;
                color: var(--text-heading);
            }
            .hint {
                color: var(--text-muted);
                font-size: 0.9rem;
                margin-top: -0.5rem;
            }
            code#api-key {
                display: block;
                background: #ece6e0;
                color: var(--text-heading);
                padding: 0.5rem 0.75rem;
                border-radius: 4px;
                word-break: break-all;
            }
            form label {
                display: block;
                margin-bottom: 0.75rem;
                font-size: 0.9rem;
                color: var(--text-body);
            }
            form label.checkbox {
                display: flex;
                align-items: center;
                gap: 0.5rem;
            }
            form input[type="text"],
            form input[type="number"],
            form select {
                display: block;
                width: 100%;
                margin-top: 0.25rem;
                padding: 0.4rem;
                border: 1px solid var(--border);
                border-radius: 4px;
                box-sizing: border-box;
                background: var(--bg);
                color: var(--text-heading);
            }
            form button {
                background: var(--accent);
                color: var(--text-heading);
                border: none;
                padding: 0.5rem 1.25rem;
                border-radius: 4px;
                cursor: pointer;
                font-weight: 600;
            }
            form button:hover {
                background: var(--accent-dark);
            }
            #config-message {
                font-size: 0.9rem;
            }
            #config-message.error {
                color: #b3261e;
            }
            #config-message.success {
                color: #3a7d44;
            }
            table {
                width: 100%;
                border-collapse: collapse;
                font-size: 0.9rem;
            }
            th, td {
                text-align: left;
                padding: 0.4rem 0.5rem;
                border-bottom: 1px solid var(--border);
                color: var(--text-body);
            }
            th {
                color: var(--text-heading);
                border-bottom: 2px solid var(--accent-light);
            }
            button {
                background: var(--accent);
                color: var(--text-heading);
                border: none;
                padding: 0.4rem 1rem;
                border-radius: 4px;
                cursor: pointer;
                font-size: 0.9rem;
                font-weight: 600;
            }
            button:hover {
                background: var(--accent-dark);
            }
            .pill {
                display: inline-block;
                padding: 0.05rem 0.5rem;
                border-radius: 999px;
                font-size: 0.78rem;
                font-weight: 600;
                white-space: nowrap;
            }
            .pill.connected   { background: #dcefdf; color: #2b6636; }
            .pill.banned      { background: #f4d4cf; color: #8c2f21; }
            .pill.blacklisted { background: #4a1f1a; color: #fdfdfd; }
            .pill.backoff     { background: #fbe9c4; color: #7d5208; }
            .pill.idle        { background: #e8e4e0; color: #55565c; }
            .pill.plain       { background: #e4e9ee; color: #4d5b69; }
            .score-high { color: #2b6636; font-weight: 600; }
            .score-mid  { color: #9a6408; font-weight: 600; }
            .score-low  { color: #a8402f; font-weight: 600; }
            .sub { display: block; font-size: 0.75rem; color: var(--text-muted); }
            #peertable td, #peertable th { padding: 0.3rem 0.4rem; vertical-align: top; }
            .peer-scroll { max-height: 560px; overflow-y: auto; }
            #peertable th { position: sticky; top: 0; background: var(--surface); }
            button.unban-btn {
                padding: 0.2rem 0.6rem;
                font-size: 0.8rem;
            }
            .danger-zone {
                border-color: var(--copper);
            }
            .danger-zone button {
                background: #a8402f;
                color: #fdfdfd;
            }
            .danger-zone button:hover {
                background: #8c3527;
            }
            #stop-message {
                font-size: 0.9rem;
                color: #a8402f;
            }
            #rpc-output {
                background: #19191a;
                color: #f0ebe5;
                padding: 0.75rem;
                border-radius: 4px;
                overflow-x: auto;
                white-space: pre-wrap;
                word-break: break-word;
                font-size: 0.85rem;
                max-height: 400px;
                overflow-y: auto;
            }
            #rpc-form label {
                margin-bottom: 0.5rem;
                color: var(--text-body);
            }
            #rpc-form textarea {
                width: 100%;
                box-sizing: border-box;
                font-family: monospace;
                padding: 0.4rem;
                border: 1px solid var(--border);
                border-radius: 4px;
                background: var(--bg);
                color: var(--text-heading);
            }
            """;

    /**
     * Metadata for every RPC method this project implements, used to
     * populate the dropdown and dynamically build each method's input
     * form. Built directly from RpcServer.java's actual dispatch switch
     * and each handler's real parameter-parsing calls (not from memory
     * or the general hsd spec), so this reflects exactly what this
     * project's RPC server actually accepts -- including real,
     * deliberate deviations like estimatefee taking no parameters at
     * all despite real hsd's version accepting one.
     */
    static final String RPC_METHODS_JS = """
            const RPC_METHODS = {
              "addnode": { params: [
                {name:"node", type:"string", required:true},
                {name:"command (add/remove/onetry)", type:"string", required:true}
              ]},
              "clearbanned": { params: [] },
              "createmultisig": { params: [
                {name:"nrequired", type:"number", required:true},
                {name:"pubkeys", type:"json", required:true}
              ]},
              "createrawtransaction": { params: [
                {name:"inputs", type:"json", required:true},
                {name:"outputs", type:"json", required:true},
                {name:"locktime", type:"number", required:false}
              ]},
              "decoderawtransaction": { params: [
                {name:"hexstring", type:"string", required:true}
              ]},
              "decodescript": { params: [
                {name:"hexstring", type:"string", required:true}
              ]},
              "disconnectnode": { params: [
                {name:"node", type:"string", required:true}
              ]},
              "estimatefee": { params: [] },
              "estimatesmartfee": { params: [
                {name:"conf_target", type:"number", required:false}
              ]},
              "getaddednodeinfo": { params: [
                {name:"node", type:"string", required:true}
              ]},
              "getbestblockhash": { params: [] },
              "getblock": { params: [
                {name:"blockhash or height", type:"string", required:true},
                {name:"verbose", type:"boolean", required:false, default:true}
              ]},
              "getblockbyheight": { params: [
                {name:"height", type:"number", required:true},
                {name:"verbose", type:"boolean", required:false, default:true}
              ]},
              "getblockchaininfo": { params: [] },
              "getblockcount": { params: [] },
              "getblockhash": { params: [
                {name:"height", type:"number", required:true}
              ]},
              "getblockheader": { params: [
                {name:"blockhash or height", type:"string", required:true},
                {name:"verbose", type:"boolean", required:false, default:true}
              ]},
              "getchaintips": { params: [] },
              "getconnectioncount": { params: [] },
              "getblocktemplate": { params: [
                {name:"address", type:"string", required:true}
              ]},
              "getdifficulty": { params: [] },
              "getinfo": { params: [] },
              "getmemoryinfo": { params: [] },
              "getmempoolancestors": { params: [
                {name:"txid", type:"string", required:true},
                {name:"verbose", type:"boolean", required:false}
              ]},
              "getmempooldescendants": { params: [
                {name:"txid", type:"string", required:true},
                {name:"verbose", type:"boolean", required:false}
              ]},
              "getmempoolentry": { params: [
                {name:"txid", type:"string", required:true}
              ]},
              "getmempoolinfo": { params: [] },
              "getnamebyhash": { params: [
                {name:"hash", type:"string", required:true}
              ]},
              "getnameinfo": { params: [
                {name:"name", type:"string", required:true}
              ]},
              "getnameproof": { params: [
                {name:"name", type:"string", required:true},
                {name:"root", type:"string", required:false}
              ]},
              "getnameresource": { params: [
                {name:"name", type:"string", required:true}
              ]},
              "getnames": { params: [] },
              "getnettotals": { params: [] },
              "getnetworkinfo": { params: [] },
              "getpeerinfo": { params: [] },
              "getrawmempool": { params: [
                {name:"verbose", type:"boolean", required:false}
              ]},
              "getrawtransaction": { params: [
                {name:"txid", type:"string", required:true},
                {name:"verbose", type:"boolean", required:false, default:false}
              ]},
              "gettxout": { params: [
                {name:"txid", type:"string", required:true},
                {name:"vout", type:"number", required:true}
              ]},
              "gettxoutproof": { params: [
                {name:"txids", type:"json", required:true},
                {name:"blockhash", type:"string", required:false}
              ]},
              "gettxoutsetinfo": { params: [] },
              "help": { params: [] },
              "listbanned": { params: [] },
              "ping": { params: [] },
              "prioritisetransaction": { params: [
                {name:"txid", type:"string", required:true}
              ]},
              "pruneblockchain": { params: [] },
              "submitblock": { params: [
                {name:"block hex", type:"string", required:true}
              ]},
              "sendrawtransaction": { params: [
                {name:"hexstring", type:"string", required:true}
              ]},
              "setban": { params: [
                {name:"ip", type:"string", required:true},
                {name:"command (add/remove)", type:"string", required:true}
              ]},
              "signmessagewithprivkey": { params: [
                {name:"privkey (WIF)", type:"string", required:true},
                {name:"message", type:"string", required:true}
              ]},
              "stop": { params: [] },
              "validateaddress": { params: [
                {name:"address", type:"string", required:true}
              ]},
              "verifyblock": { params: [
                {name:"block hex", type:"string", required:true}
              ]},
              "verifymessage": { params: [
                {name:"address", type:"string", required:true},
                {name:"signature", type:"string", required:true},
                {name:"message", type:"string", required:true}
              ]},
              "verifymessagewithname": { params: [
                {name:"name", type:"string", required:true},
                {name:"signature", type:"string", required:true},
                {name:"message", type:"string", required:true}
              ]},
              "verifytxoutproof": { params: [
                {name:"proof hex", type:"string", required:true}
              ]}
            };
            """;

    public static final String APP_JS = """
            document.addEventListener("DOMContentLoaded", () => {
                loadApiKey();
                loadConfig();
                refreshAll();
                setInterval(refreshAll, 2000);

                document.getElementById("config-form").addEventListener("submit", onSaveConfig);
                document.getElementById("stop-node-btn").addEventListener("click", onStopNode);

                setupRpcPanel();
            });
""" + RPC_METHODS_JS + """

            function setupRpcPanel() {
                const select = document.getElementById("rpc-method-select");
                const names = Object.keys(RPC_METHODS).sort();
                select.innerHTML = names.map(n => `<option value="${n}">${n}</option>`).join("");
                select.addEventListener("change", () => renderRpcForm(select.value));
                renderRpcForm(select.value);

                document.getElementById("rpc-form").addEventListener("submit", onSubmitRpc);
            }

            function renderRpcForm(methodName) {
                const form = document.getElementById("rpc-form");
                const method = RPC_METHODS[methodName];
                if (!method || method.params.length === 0) {
                    form.innerHTML = "<p class=\\"hint\\">This method takes no parameters.</p>";
                    return;
                }
                form.innerHTML = method.params.map(p => {
                    const req = p.required ? " (required)" : " (optional)";
                    if (p.type === "boolean") {
                        return `<label class="checkbox"><input type="checkbox" name="${p.name}" ${p.default ? "checked" : ""}> ${p.name}${req}</label>`;
                    }
                    if (p.type === "json") {
                        return `<label>${p.name}${req} (JSON)<textarea name="${p.name}" rows="2" placeholder='e.g. ["a","b"] or {"key":"value"}'></textarea></label>`;
                    }
                    const inputType = p.type === "number" ? "number" : "text";
                    return `<label>${p.name}${req}<input type="${inputType}" name="${p.name}"></label>`;
                }).join("");
            }

            async function onSubmitRpc(event) {
                event.preventDefault();
                const select = document.getElementById("rpc-method-select");
                const methodName = select.value;
                const method = RPC_METHODS[methodName];
                const form = event.target;
                const output = document.getElementById("rpc-output");

                const paramsArray = [];
                for (const p of method.params) {
                    const el = form.elements[p.name];
                    if (p.type === "boolean") {
                        paramsArray.push(el.checked);
                        continue;
                    }
                    const raw = el.value.trim();
                    if (raw === "") {
                        if (p.required) {
                            output.textContent = "Missing required parameter: " + p.name;
                            return;
                        }
                        continue; // omit trailing optional params entirely
                    }
                    if (p.type === "number") {
                        paramsArray.push(Number(raw));
                    } else if (p.type === "json") {
                        try {
                            paramsArray.push(JSON.parse(raw));
                        } catch (e) {
                            output.textContent = "Invalid JSON in " + p.name + ": " + e.message;
                            return;
                        }
                    } else {
                        paramsArray.push(raw);
                    }
                }

                output.textContent = "Loading...";
                try {
                    const res = await fetch("/api/rpc", {
                        method: "POST",
                        headers: { "Content-Type": "application/json" },
                        body: JSON.stringify({ method: methodName, params: paramsArray, id: 1 })
                    });
                    const text = await res.text();
                    try {
                        output.textContent = JSON.stringify(JSON.parse(text), null, 2);
                    } catch (e) {
                        output.textContent = text;
                    }
                } catch (e) {
                    output.textContent = "Failed to reach RPC proxy: " + e.message;
                }
            }

            function refreshAll() {
                loadStatus();
                loadPeerTable();
                loadMempool();
            }

            async function loadStatus() {
                try {
                    const res = await fetch("/api/status");
                    const data = await res.json();
                    document.getElementById("version").textContent = data.version;
                    document.getElementById("uptime").textContent = data.uptime;
                    document.getElementById("block-height").textContent = data.blockHeight;
                    // syncPercent is null until at least one peer has
                    // announced its height (see WebAdminServer's own
                    // comment on why null rather than a misleading 0%).
                    const syncEl = document.getElementById("sync-percent");
                    if (data.syncPercent === null) {
                        syncEl.textContent = "Waiting for peers...";
                    } else {
                        syncEl.textContent = data.syncPercent + "% (block "
                            + data.blockHeight + " of " + data.networkHeight + ")";
                    }
                    document.getElementById("db-size").textContent = data.dbSizeGB + " GB";

                    // FIX (audit): the backend already tracked and exposed
                    // this halt state (ChainSync.haltedDueToTreeMismatch())
                    // internally, but nothing ever surfaced it here -- a
                    // real halt would previously only be visible in
                    // console/log output, never in this admin panel.
                    const haltBanner = document.getElementById("halt-banner");
                    if (data.halted) {
                        document.getElementById("halt-height").textContent = data.halted.height;
                        haltBanner.style.display = "block";
                    } else {
                        haltBanner.style.display = "none";
                    }
                } catch (e) {
                    document.getElementById("uptime").textContent = "Unavailable";
                }
            }

            function fmtAgo(ts) {
                if (!ts) return "never";
                const sec = Math.max(0, Math.floor((Date.now() - ts) / 1000));
                if (sec < 60) return sec + "s ago";
                if (sec < 3600) return Math.floor(sec / 60) + "m ago";
                if (sec < 86400) return Math.floor(sec / 3600) + "h ago";
                return Math.floor(sec / 86400) + "d ago";
            }

            function fmtDur(ms) {
                const sec = Math.ceil(ms / 1000);
                if (sec < 60) return sec + "s";
                if (sec < 3600) return Math.ceil(sec / 60) + "m";
                return Math.round(sec / 3600) + "h";
            }

            function scoreClass(n) {
                return n >= 70 ? "score-high" : (n >= 40 ? "score-mid" : "score-low");
            }

            function pillFor(p) {
                switch (p.state) {
                    case "banned":
                        return '<span class="pill banned">Banned</span>';
                    case "connected":
                        return '<span class="pill connected">Connected &middot; ' + escapeHtml(p.direction)
                            + (p.transport === "plain" ? ' &middot; cleartext' : '') + '</span>';
                    case "blacklisted":
                        return '<span class="pill blacklisted">Blacklisted</span>';
                    case "backoff":
                        return '<span class="pill backoff">Backoff ' + fmtDur(p.backoffMs) + '</span>';
                    case "plain":
                        return '<span class="pill plain">Cleartext</span>';
                    default:
                        return '<span class="pill idle" title="Known peer with a key; no open connection right now">Not connected</span>';
                }
            }

            function tooltipFor(p) {
                const lines = [
                    p.ip + ":" + p.port + (p.label ? " (" + p.label + ")" : ""),
                    "source: " + (p.source || "unknown") + (p.seed ? " (seed)" : ""),
                    "transport: " + (p.state === "connected" ? p.transport : (p.hasKey ? "brontide" : "cleartext (no brontide key)")),
                    "agent: " + (p.agent || "?") + "  height: " + (p.height || "?"),
                    "successes: " + p.successes + "  failures: " + p.failures,
                    "valid data: " + p.validData + "  invalid data: " + p.invalidData,
                    "avg latency: " + (p.latencyMs >= 0 ? p.latencyMs + " ms" : "n/a"),
                    "last failure: " + fmtAgo(p.lastFailure)
                ];
                if (p.penalties && p.penalties.length) {
                    lines.push("recent penalties (this run):");
                    p.penalties.forEach(x => lines.push("  " + x));
                }
                if (p.state === "banned") {
                    lines.push("ban reason: " + (p.banReason || ""));
                }
                return lines.join(String.fromCharCode(10));
            }

            async function loadPeerTable() {
                const tbody = document.querySelector("#peertable tbody");
                const summary = document.getElementById("peers-summary");
                try {
                    const res = await fetch("/api/peertable");
                    const peers = await res.json();
                    const count = st => peers.filter(p => p.state === st).length;
                    // "Verified" = we actually talked to it (connected now, ever succeeded, or a curated seed).
                    // Everything else is just an address another node mentioned in gossip: it may be
                    // stale, unreachable or junk, so it is counted and shown separately.
                    const isVerified = p => p.state === "connected" || p.successes > 0 || p.seed;
                    const verified = peers.filter(isVerified);
                    // Peers we tried but never reached (backoff/banned/blacklisted) stay visible; only
                    // addresses we have never even attempted count as "gossip only".
                    const isGossipOnly = p => !isVerified(p) && p.state !== "backoff"
                        && p.state !== "banned" && p.state !== "blacklisted";
                    const unverified = peers.filter(isGossipOnly).length;
                    summary.textContent = count("connected") + " connected \u00b7 "
                        + count("backoff") + " backed off \u00b7 "
                        + count("banned") + " banned \u00b7 "
                        + verified.length + " verified \u00b7 "
                        + unverified + " unverified gossip addresses";
                    let toggle = document.getElementById("peers-toggle");
                    if (!toggle) {
                        summary.insertAdjacentHTML("afterend",
                            '<p><button id="peers-toggle" class="unban-btn"></button></p>');
                        toggle = document.getElementById("peers-toggle");
                        toggle.addEventListener("click", () => {
                            window.showUnverifiedPeers = !window.showUnverifiedPeers;
                            loadPeerTable();
                        });
                    }
                    toggle.textContent = (window.showUnverifiedPeers ? "Hide" : "Show")
                        + " " + unverified + " unverified gossip addresses";
                    if (!window.showUnverifiedPeers) {
                        peers.splice(0, peers.length, ...peers.filter(p => !isGossipOnly(p)));
                    }
                    if (peers.length === 0) {
                        tbody.innerHTML = '<tr><td colspan="3">No peers to show yet.</td></tr>';
                        return;
                    }
                    peers.sort((a, b) => (b.score - a.score) || a.ip.localeCompare(b.ip));
                    tbody.innerHTML = peers.map(p => `
                        <tr title="${escapeHtml(tooltipFor(p))}">
                            <td>${escapeHtml(p.ip)}${p.seed ? " &#9733;" : ""}
                                <span class="sub">${escapeHtml(p.agent || (p.label || p.source || ""))}${p.height ? " &middot; " + p.height : ""}</span></td>
                            <td>${pillFor(p)}${p.state === "banned"
                                ? ' <button class="unban-btn" data-ip="' + escapeHtml(p.ip) + '">Unban</button>'
                                    + '<span class="sub">' + escapeHtml(p.banReason || "") + '</span>'
                                : ""}</td>
                            <td class="${scoreClass(p.score)}">${p.score}</td>
                        </tr>
                    `).join("");
                    tbody.querySelectorAll(".unban-btn").forEach(btn => {
                        btn.addEventListener("click", () => onUnban(btn.dataset.ip));
                    });
                } catch (e) {
                    tbody.innerHTML = '<tr><td colspan="3">Failed to load.</td></tr>';
                }
            }

            async function loadMempool() {
                try {
                    const res = await fetch("/api/mempool");
                    const data = await res.json();
                    document.getElementById("mempool-count").textContent = data.count;
                    document.getElementById("mempool-bytes").textContent = formatBytes(data.bytes) + " / " + formatBytes(data.maxBytes);
                    document.getElementById("mempool-fee").textContent = (data.minRelayFeeRate / 1000000) + " HNS/kB";
                } catch (e) {
                    document.getElementById("mempool-count").textContent = "Unavailable";
                }
            }

            async function onUnban(ip) {
                try {
                    await fetch("/api/bans/unban", {
                        method: "POST",
                        headers: { "Content-Type": "application/json" },
                        body: JSON.stringify({ ip })
                    });
                    loadPeerTable();
                } catch (e) { /* silently retry on next poll */ }
            }

            async function onStopNode() {
                if (!confirm("Stop the node? This will shut it down gracefully.")) return;
                const message = document.getElementById("stop-message");
                try {
                    const res = await fetch("/api/stop", { method: "POST" });
                    const data = await res.json();
                    message.textContent = data.message || "Stopping...";
                } catch (e) {
                    message.textContent = "Node has stopped (connection closed).";
                }
            }

            function formatBytes(bytes) {
                if (bytes < 1024) return bytes + " B";
                if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + " KB";
                return (bytes / (1024 * 1024)).toFixed(1) + " MB";
            }

            // Escapes all five HTML-significant characters. The previous
            // textContent/innerHTML trick only escaped & < > and left quotes
            // alone, which is unsafe in attribute context such as
            // data-ip="${escapeHtml(b.ip)}" above.
            function escapeHtml(s) {
                return String(s == null ? "" : s)
                    .replace(/&/g, "&amp;")
                    .replace(/</g, "&lt;")
                    .replace(/>/g, "&gt;")
                    .replace(/"/g, "&quot;")
                    .replace(/'/g, "&#39;");
            }

            async function loadApiKey() {
                const el = document.getElementById("api-key");
                try {
                    const res = await fetch("/api/apikey");
                    const data = await res.json();
                    el.textContent = data.apiKey && data.apiKey.length > 0 ? data.apiKey : "(none set)";
                } catch (e) {
                    el.textContent = "Failed to load.";
                }
            }

            async function loadConfig() {
                const form = document.getElementById("config-form");
                try {
                    const res = await fetch("/api/config");
                    const data = await res.json();
                    form.elements["rpc.host"].value = data["rpc.host"];
                } catch (e) {
                    document.getElementById("config-message").textContent = "Failed to load current configuration.";
                    document.getElementById("config-message").className = "error";
                }
            }

            async function onSaveConfig(event) {
                event.preventDefault();
                const form = event.target;
                const message = document.getElementById("config-message");
                message.textContent = "";
                message.className = "";

                const payload = {
                    "rpc.host": form.elements["rpc.host"].value
                };

                try {
                    const res = await fetch("/api/config", {
                        method: "POST",
                        headers: { "Content-Type": "application/json" },
                        body: JSON.stringify(payload)
                    });
                    const data = await res.json();
                    if (!res.ok) {
                        message.textContent = data.error || "Save failed.";
                        message.className = "error";
                        return;
                    }
                    message.textContent = data.restartRequired
                        ? "Saved. Restart the node for these changes to take effect."
                        : "Saved.";
                    message.className = "success";
                } catch (e) {
                    message.textContent = "Save failed: could not reach the server.";
                    message.className = "error";
                }
            }
            """;
}