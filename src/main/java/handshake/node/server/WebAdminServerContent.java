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
                <meta name="viewport" content="width=device-width, initial-scale=1">
                <title>Easy Handshake Node</title>
                <script>
                    try { var t = localStorage.getItem("theme"); if (t === "light" || t === "dark") document.documentElement.setAttribute("data-theme", t); } catch (e) { /* no saved choice */ }
                </script>
                <link rel="stylesheet" href="/style.css">
            </head>
            <body>
                <header class="top">
                    <div class="brand">
                        <h1>Easy Handshake Node</h1>
                        <span class="tag">v<span id="version">...</span></span>
                    </div>
                    <div class="top-right">
                        <span class="uptime">Up <b id="uptime">...</b></span>
                        <button id="theme-btn" type="button" class="theme" title="Switch between automatic, light and dark">Theme: Auto</button>
                        <span id="live" class="live" data-state="connecting" title="Connection to the node"><i></i><span id="live-text">Connecting</span></span>
                    </div>
                </header>

                <div id="shutdown-banner" class="banner warn" role="status" hidden>
                    <b id="shutdown-title"></b> <span id="shutdown-text"></span>
                </div>
                <div id="halt-banner" class="banner bad" hidden>
                    Node halted: Urkel tree root mismatch at height <span id="halt-height"></span>.
                    This needs investigation or recovery before sync can safely resume.
                </div>
                <div id="disk-banner" class="banner warn" hidden>
                    Low disk space: <span id="disk-banner-free"></span> free on the node's drive.
                    The node shuts down cleanly below 2 GB free. Free up space or move the data directory.
                </div>

                <section class="sync" aria-label="Sync progress">
                    <div class="sync-head">
                        <div class="height"><span id="block-height">...</span><small>blocks</small></div>
                        <div class="sync-meta">
                            <span id="sync-percent" class="pct">...</span>
                            <span id="sync-note" class="muted">Waiting for peers</span>
                        </div>
                    </div>
                    <div class="bar" role="progressbar" aria-valuemin="0" aria-valuemax="100" id="sync-bar"><div id="sync-fill"></div></div>
                </section>

                <section class="tiles" aria-label="Resources">
                    <div class="tile" id="t-cpu">
                        <svg class="gauge" viewBox="0 0 100 62" aria-hidden="true"><path class="track" d="M10 54 A40 40 0 0 1 90 54" pathLength="100"/><path class="fill" d="M10 54 A40 40 0 0 1 90 54" pathLength="100" stroke-dasharray="0 100"/></svg>
                        <div class="tile-body"><div class="tile-title">CPU</div><div class="tile-val" id="cpu-val">...</div><div class="tile-sub" id="cpu-sub"></div></div>
                    </div>
                    <div class="tile" id="t-mem">
                        <svg class="gauge" viewBox="0 0 100 62" aria-hidden="true"><path class="track" d="M10 54 A40 40 0 0 1 90 54" pathLength="100"/><path class="fill" d="M10 54 A40 40 0 0 1 90 54" pathLength="100" stroke-dasharray="0 100"/></svg>
                        <div class="tile-body"><div class="tile-title">Memory</div><div class="tile-val" id="mem-val">...</div><div class="tile-sub" id="mem-sub"></div></div>
                    </div>
                    <div class="tile wide" id="t-storage">
                        <div class="tile-body">
                            <div class="stor-head">
                                <div class="tile-title">Storage</div>
                            </div>
                            <div class="stack" id="stor-bar" role="img" aria-label="Storage use"></div>
                            <div class="legend" id="stor-legend"></div>
                        </div>
                    </div>
                    <div class="tile stat" id="t-pool">
                        <div class="tile-body">
                            <div class="tile-title">Mempool</div>
                            <div class="tile-val"><span id="mempool-count">...</span> <small>transactions</small></div>
                            <div class="bar thin" id="mempool-bar"><div id="mempool-fill"></div></div>
                            <div class="tile-sub" id="mempool-bytes">...</div>
                        </div>
                    </div>
                </section>

                <main class="panes">
                    <section class="pane peers">
                        <div class="pane-head">
                            <h2>Peers</h2>
                            <div class="chips" id="peers-chips"></div>
                        </div>
                        <div class="pane-sub">
                            <span id="peers-summary" class="muted">Loading...</span>
                            <button id="peers-toggle" class="link" type="button"></button>
                        </div>
                        <div class="peer-scroll">
                            <table id="peertable">
                                <thead><tr><th>Peer</th><th>Status</th><th>Score</th></tr></thead>
                                <tbody><tr><td colspan="3">Loading...</td></tr></tbody>
                            </table>
                        </div>
                    </section>

                    <section class="pane logs">
                        <div class="pane-head">
                            <h2>Live log</h2>
                            <div class="log-tools">
                                <input id="log-filter" type="search" placeholder="Filter" aria-label="Filter log lines" spellcheck="false">
                                <label class="check"><input type="checkbox" id="log-errors"> Errors only</label>
                                <button id="log-pause" type="button" class="ghost">Pause</button>
                                <button id="log-copy" type="button" class="ghost">Copy</button>
                            </div>
                        </div>
                        <div id="log" class="log" role="log" aria-live="off" tabindex="0"></div>
                        <button id="log-jump" type="button" class="jump" hidden></button>
                    </section>
                </main>

                <details class="tools">
                    <summary>Settings and tools</summary>
                    <div class="tools-grid">
                        <section class="panel">
                            <h2>Settings</h2>
                            <form id="config-form">
                                <label>RPC host
                                    <input type="text" name="rpc.host"></label>
                                <label>Mining reward address (hs1...)
                                    <input type="text" name="miner.address" placeholder="Leave empty to disable mining" spellcheck="false"></label>
                                <p class="hint">Changing the RPC host needs a restart. Miners that connect (getwork) are paid to the reward address; that applies immediately.</p>
                                <button type="submit">Save changes</button>
                            </form>
                            <p id="config-message"></p>
                        </section>

                        <section class="panel">
                            <h2>RPC console</h2>
                            <label>Method
                                <select id="rpc-method-select"></select></label>
                            <form id="rpc-form"></form>
                            <button id="rpc-submit-btn" type="submit" form="rpc-form">Run</button>
                            <pre id="rpc-output">(no call made yet)</pre>
                        </section>

                        <section class="panel">
                            <h2>Access</h2>
                            <p class="hint">Needed for RPC calls made from anywhere other than this machine.</p>
                            <code id="api-key">Loading...</code>
                            <div class="danger">
                                <h2>Stop the node</h2>
                                <p class="hint">Shuts the node down gracefully.</p>
                                <button id="stop-node-btn" type="button" class="bad">Stop node</button>
                                <p id="stop-message"></p>
                            </div>
                        </section>
                    </div>
                </details>
                <script src="/app.js"></script>
            </body>
            </html>
            """;

    public static final String STYLE_CSS = """
            :root {
                color-scheme: light dark;
                --bg: #eef1f4;
                --panel: #ffffff;
                --line: #dbe1e8;
                --ink: #16202b;
                --body: #3f4c5a;
                --muted: #6a7888;
                --accent: #1d6f8e;
                --accent-ink: #ffffff;
                --track: #e3e8ee;
                --ok: #2a8a57;
                --warn: #c0840f;
                --bad: #c2412d;
                --log-bg: #f7f9fb;
                --log-err: #b3321f;
                --radius: 8px;
            }
            @media (prefers-color-scheme: dark) {
                :root:not([data-theme="light"]) {
                    color-scheme: dark;
                    --bg: #11161c;
                    --panel: #192028;
                    --line: #2a3541;
                    --ink: #e6ecf2;
                    --body: #b4c0cd;
                    --muted: #8392a2;
                    --accent: #58b3d3;
                    --accent-ink: #0b1218;
                    --track: #27323d;
                    --ok: #4cc283;
                    --warn: #e0a83a;
                    --bad: #ee6f5a;
                    --log-bg: #131a21;
                    --log-err: #f08a79;
                }
            }
            :root[data-theme="dark"] {
                color-scheme: dark;
                --bg: #11161c;
                    --panel: #192028;
                    --line: #2a3541;
                    --ink: #e6ecf2;
                    --body: #b4c0cd;
                    --muted: #8392a2;
                    --accent: #58b3d3;
                    --accent-ink: #0b1218;
                    --track: #27323d;
                    --ok: #4cc283;
                    --warn: #e0a83a;
                    --bad: #ee6f5a;
                    --log-bg: #131a21;
                    --log-err: #f08a79;
            }
            :root[data-theme="light"] { color-scheme: light; }
            * { box-sizing: border-box; }
            body {
                margin: 0 auto;
                max-width: 1640px;
                padding: 0.75rem 1rem 2rem;
                background: var(--bg);
                color: var(--body);
                font: 14px/1.45 "Segoe UI Variable", "Segoe UI", system-ui, -apple-system, sans-serif;
                font-variant-numeric: tabular-nums;
            }
            h1, h2 { color: var(--ink); margin: 0; }
            h1 { font-size: 1.15rem; font-weight: 650; letter-spacing: -0.01em; }
            h2 { font-size: 0.95rem; font-weight: 650; }
            .muted { color: var(--muted); }
            .hint { color: var(--muted); font-size: 0.85rem; margin: 0.25rem 0 0.6rem; }
            b { color: var(--ink); font-weight: 600; }
            button:focus-visible, input:focus-visible, select:focus-visible, summary:focus-visible, .log:focus-visible {
                outline: 2px solid var(--accent);
                outline-offset: 2px;
            }

            /* top bar */
            .top { display: flex; align-items: center; justify-content: space-between; gap: 1rem; padding: 0.25rem 0 0.75rem; }
            .brand { display: flex; align-items: baseline; gap: 0.6rem; }
            .tag { color: var(--muted); font-size: 0.85rem; }
            .top-right { display: flex; align-items: center; gap: 1rem; color: var(--muted); }
            button.theme { background: transparent; color: var(--muted); border: 1px solid var(--line); font-weight: 500; padding: 0.15rem 0.6rem; font-size: 0.82rem; }
            .live { display: inline-flex; align-items: center; gap: 0.4rem; font-weight: 600; color: var(--ink); }
            .live i { width: 9px; height: 9px; border-radius: 50%; background: var(--muted); }
            .live[data-state="live"] i { background: var(--ok); box-shadow: 0 0 0 3px color-mix(in srgb, var(--ok) 25%, transparent); }
            .live[data-state="connecting"] i, .live[data-state="polling"] i { background: var(--warn); }
            .live[data-state="down"] i { background: var(--bad); }

            .banner { padding: 0.6rem 0.9rem; border-radius: var(--radius); font-weight: 600; margin-bottom: 0.75rem; color: #fff; }
            .banner[hidden] { display: none; }
            .banner.bad { background: var(--bad); }
            .banner.warn { background: var(--warn); color: #1a1303; }
            .banner.ok { background: var(--ok); color: #04150b; }

            /* sync strip: the one big element */
            .sync { background: var(--panel); border: 1px solid var(--line); border-radius: var(--radius); padding: 0.85rem 1.1rem 1rem; margin-bottom: 0.75rem; }
            .sync-head { display: flex; align-items: flex-end; justify-content: space-between; gap: 1rem; margin-bottom: 0.6rem; }
            .height { color: var(--ink); font-size: 2.4rem; line-height: 1; font-weight: 650; letter-spacing: -0.02em; }
            .height small { font-size: 0.9rem; font-weight: 500; color: var(--muted); margin-left: 0.5rem; letter-spacing: 0; }
            .sync-meta { display: flex; align-items: baseline; gap: 0.75rem; text-align: right; flex-wrap: wrap; justify-content: flex-end; }
            .pct { color: var(--ink); font-size: 1.25rem; font-weight: 650; }
            .bar { height: 10px; background: var(--track); border-radius: 99px; overflow: hidden; }
            .bar > div { height: 100%; width: 0; background: var(--accent); border-radius: 99px; transition: width 0.4s ease, background-color 0.3s; }
            .bar.thin { height: 6px; margin: 0.35rem 0 0.25rem; }
            .bar.done > div { background: var(--ok); }

            /* resource tiles */
            .tiles { display: grid; grid-template-columns: repeat(5, minmax(0, 1fr)); gap: 0.75rem; margin-bottom: 0.75rem; }
            .tile { background: var(--panel); border: 1px solid var(--line); border-radius: var(--radius); padding: 0.6rem 0.9rem; display: flex; align-items: center; gap: 0.7rem; min-height: 84px; }
            .tile.stat { padding-top: 0.7rem; }
            .tile-body { min-width: 0; flex: 1; }
            .tile-title { color: var(--muted); font-size: 0.8rem; }
            .tile-val { color: var(--ink); font-size: 1.35rem; font-weight: 650; line-height: 1.2; letter-spacing: -0.01em; }
            .tile-val small { font-size: 0.78rem; font-weight: 500; color: var(--muted); letter-spacing: 0; }
            .tile-sub { color: var(--muted); font-size: 0.78rem; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
            .gauge { width: 84px; height: 52px; flex: none; }
            .gauge path { fill: none; stroke-width: 9; stroke-linecap: round; }
            .gauge .track { stroke: var(--track); }
            .gauge .fill { stroke: var(--accent); transition: stroke-dasharray 0.5s ease, stroke 0.3s; }
            .tile[data-level="warn"] .gauge .fill { stroke: var(--warn); }
            .tile[data-level="bad"] .gauge .fill { stroke: var(--bad); }

            /* storage panel */
            :root { --c-sys: #d9534f; --c-node: #e6b800; --c-free: #2a8a57; }
            @media (prefers-color-scheme: dark) {
                :root:not([data-theme="light"]) { --c-sys: #ee6f5a; --c-node: #f0c93a; --c-free: #4cc283; }
            }
            :root[data-theme="dark"] { --c-sys: #ee6f5a; --c-node: #f0c93a; --c-free: #4cc283; }
            .tile.wide { grid-column: span 2; }
            .stor-head { display: flex; align-items: baseline; justify-content: space-between; gap: 0.75rem; flex-wrap: wrap; }
            .stack { display: flex; height: 16px; margin: 0.35rem 0 0.45rem; border: 1px solid var(--line); border-radius: 99px; overflow: hidden; background: transparent; }
            .stack[data-level="warn"] { border-color: var(--warn); }
            .stack[data-level="bad"] { border-color: var(--bad); }
            .stack > span { display: block; height: 100%; min-width: 2px; flex: 0 0 auto; transition: flex-basis 0.5s ease; }
            .stack > span + span { box-shadow: -1px 0 0 var(--panel); }
            .legend { display: flex; flex-wrap: wrap; gap: 0.1rem 0.9rem; font-size: 0.74rem; color: var(--muted); line-height: 1.5; }
            .legend > span { white-space: nowrap; }
            .legend i { display: inline-block; width: 9px; height: 9px; border-radius: 3px; margin-right: 0.3rem; vertical-align: -1px; }
            .legend b { color: var(--body); font-weight: 600; }

            /* panes */
            .panes { display: grid; grid-template-columns: minmax(0, 5fr) minmax(0, 7fr); gap: 0.75rem; align-items: stretch; margin-bottom: 0.75rem; }
            .pane { background: var(--panel); border: 1px solid var(--line); border-radius: var(--radius); padding: 0.7rem 0.9rem 0.8rem; display: flex; flex-direction: column; min-width: 0; height: 560px; position: relative; }
            .pane-head { display: flex; align-items: center; justify-content: space-between; gap: 0.75rem; margin-bottom: 0.4rem; flex-wrap: wrap; }
            .pane-sub { display: flex; align-items: center; justify-content: space-between; gap: 0.5rem; font-size: 0.82rem; margin-bottom: 0.4rem; }
            .chips { display: flex; gap: 0.35rem; flex-wrap: wrap; }
            .chip { font-size: 0.78rem; padding: 0.05rem 0.55rem; border-radius: 99px; background: var(--track); color: var(--body); white-space: nowrap; }
            .chip.ok { background: color-mix(in srgb, var(--ok) 20%, transparent); color: var(--ok); }
            .chip.warn { background: color-mix(in srgb, var(--warn) 22%, transparent); color: var(--warn); }
            .chip.bad { background: color-mix(in srgb, var(--bad) 20%, transparent); color: var(--bad); }

            table { width: 100%; border-collapse: collapse; font-size: 0.86rem; }
            th { text-align: left; font-weight: 600; color: var(--muted); font-size: 0.78rem; padding: 0.25rem 0.4rem; border-bottom: 1px solid var(--line); position: sticky; top: 0; background: var(--panel); }
            td { padding: 0.28rem 0.4rem; border-bottom: 1px solid color-mix(in srgb, var(--line) 60%, transparent); vertical-align: middle; }
            .peer-scroll { overflow-y: auto; flex: 1; min-height: 0; }
            .sub { display: block; font-size: 0.74rem; color: var(--muted); line-height: 1.2; }
            .pill { display: inline-block; padding: 0 0.5rem; border-radius: 99px; font-size: 0.76rem; font-weight: 600; white-space: nowrap; }
            .pill.connected   { background: color-mix(in srgb, var(--ok) 20%, transparent); color: var(--ok); }
            .pill.banned      { background: color-mix(in srgb, var(--bad) 20%, transparent); color: var(--bad); }
            .pill.blacklisted { background: var(--bad); color: #fff; }
            .pill.backoff     { background: color-mix(in srgb, var(--warn) 22%, transparent); color: var(--warn); }
            .pill.idle, .pill.plain { background: var(--track); color: var(--body); }
            .score { display: inline-flex; align-items: center; gap: 0.4rem; font-weight: 600; }
            .score i { display: inline-block; width: 34px; height: 5px; border-radius: 3px; background: var(--track); position: relative; overflow: hidden; }
            .score i::after { content: ""; position: absolute; inset: 0 auto 0 0; width: var(--w, 0%); background: currentColor; border-radius: 3px; }
            .score-high { color: var(--ok); } .score-mid { color: var(--warn); } .score-low { color: var(--bad); }

            /* log */
            .log-tools { display: flex; align-items: center; gap: 0.5rem; flex-wrap: wrap; }
            .log-tools input[type="search"] { width: 150px; }
            .check { display: inline-flex; align-items: center; gap: 0.3rem; font-size: 0.82rem; color: var(--muted); }
            .log { flex: 1; min-height: 0; overflow-y: auto; background: var(--log-bg); border: 1px solid var(--line); border-radius: 6px; padding: 0.4rem 0.6rem; font: 12px/1.5 ui-monospace, "Cascadia Mono", Consolas, monospace; }
            .log .ln { white-space: pre-wrap; word-break: break-word; color: var(--body); }
            .log .ln time { color: var(--muted); margin-right: 0.6rem; }
            .log .ln .tg { color: var(--accent); }
            .log .ln.err { color: var(--log-err); }
            .log .ln.err .tg { color: inherit; }
            .jump { position: absolute; right: 1.5rem; bottom: 1.4rem; box-shadow: 0 2px 8px rgba(0,0,0,0.25); }

            /* controls */
            button { font: inherit; font-weight: 600; background: var(--accent); color: var(--accent-ink); border: 0; border-radius: 6px; padding: 0.35rem 0.95rem; cursor: pointer; }
            button:hover { filter: brightness(1.08); }
            button.ghost { background: transparent; color: var(--accent); border: 1px solid var(--line); padding: 0.18rem 0.65rem; font-weight: 500; }
            button.link { background: none; color: var(--accent); padding: 0; font-weight: 500; }
            button.bad { background: var(--bad); color: #fff; }
            button.unban-btn { padding: 0.05rem 0.5rem; font-size: 0.76rem; margin-left: 0.3rem; }
            input[type="text"], input[type="number"], input[type="search"], select, textarea {
                font: inherit; color: var(--ink); background: var(--bg); border: 1px solid var(--line); border-radius: 6px; padding: 0.3rem 0.5rem; width: 100%;
            }
            .log-tools input[type="search"] { width: 150px; }
            label { display: block; font-size: 0.85rem; margin-bottom: 0.55rem; color: var(--body); }
            label.checkbox { display: flex; align-items: center; gap: 0.4rem; }
            label.checkbox input { width: auto; }

            /* tools */
            .tools { background: var(--panel); border: 1px solid var(--line); border-radius: var(--radius); padding: 0.55rem 0.9rem; }
            .tools > summary { cursor: pointer; font-weight: 650; color: var(--ink); }
            .tools[open] > summary { margin-bottom: 0.7rem; }
            .tools-grid { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 0.9rem; }
            .panel h2 { margin-bottom: 0.4rem; }
            .panel + .panel { border-left: 1px solid var(--line); padding-left: 0.9rem; }
            #config-message.error { color: var(--bad); } #config-message.success { color: var(--ok); }
            code#api-key { display: block; background: var(--bg); border: 1px solid var(--line); padding: 0.35rem 0.55rem; border-radius: 6px; word-break: break-all; color: var(--ink); }
            .danger { margin-top: 1rem; padding-top: 0.7rem; border-top: 1px solid var(--line); }
            #stop-message { color: var(--bad); font-size: 0.85rem; }
            #rpc-output { background: #10161c; color: #e6ecf2; padding: 0.55rem; border-radius: 6px; white-space: pre-wrap; word-break: break-word; font-size: 0.8rem; max-height: 320px; overflow: auto; margin: 0.6rem 0 0; }
            #rpc-form textarea { font-family: ui-monospace, Consolas, monospace; }

            @media (max-width: 1250px) { .tiles { grid-template-columns: repeat(3, minmax(0, 1fr)); } }
            @media (max-width: 1000px) {
                .panes { grid-template-columns: 1fr; }
                .pane { height: 460px; }
                .tools-grid { grid-template-columns: 1fr; }
                .panel + .panel { border-left: 0; padding-left: 0; }
            }
            @media (max-width: 640px) {
                .tiles { grid-template-columns: repeat(2, minmax(0, 1fr)); }
                .height { font-size: 1.9rem; }
                .sync-head { flex-direction: column; align-items: flex-start; }
            }
            @media (prefers-reduced-motion: reduce) { * { transition: none !important; } }
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
              "compacttree": { params: [] },
              "reconstructtree": { params: [] },
              "resetrootcache": { params: [] },
              "decoderesource": { params: [
                {name:"hex", type:"string", required:true}
              ]},
              "validateresource": { params: [
                {name:"resource", type:"json", required:true}
              ]},
              "estimatepriority": { params: [
                {name:"nblocks", type:"number", required:true}
              ]},
              "estimatesmartpriority": { params: [
                {name:"nblocks", type:"number", required:true}
              ]},
              "generate": { params: [
                {name:"numblocks", type:"number", required:true},
                {name:"maxtries", type:"number", required:false}
              ]},
              "generatetoaddress": { params: [
                {name:"numblocks", type:"number", required:true},
                {name:"address", type:"string", required:true},
                {name:"maxtries", type:"number", required:false}
              ]},
              "getdnssecproof": { params: [
                {name:"name", type:"string", required:true},
                {name:"estimate", type:"boolean", required:false},
                {name:"verbose", type:"boolean", required:false}
              ]},
              "getgenerate": { params: [] },
              "getmininginfo": { params: [] },
              "getmineraddress": { params: [] },
              "setmineraddress": { params: [
                {name:"address", type:"string", required:true}
              ]},
              "getnetworkhashps": { params: [
                {name:"blocks", type:"number", required:false},
                {name:"height", type:"number", required:false}
              ]},
              "getwork": { params: [] },
              "getworklp": { params: [] },
              "grindname": { params: [
                {name:"size", type:"number", required:false}
              ]},
              "invalidateblock": { params: [
                {name:"hash", type:"string", required:true}
              ]},
              "reconsiderblock": { params: [
                {name:"hash", type:"string", required:true}
              ]},
              "sendrawairdrop": { params: [
                {name:"base64-string", type:"string", required:true}
              ]},
              "sendrawclaim": { params: [
                {name:"base64-string", type:"string", required:true}
              ]},
              "setgenerate": { params: [
                {name:"mine", type:"boolean", required:true},
                {name:"proclimit", type:"number", required:false}
              ]},
              "setloglevel": { params: [
                {name:"level", type:"string", required:true}
              ]},
              "setmocktime": { params: [
                {name:"timestamp", type:"number", required:true}
              ]},
              "signrawtransaction": { params: [
                {name:"hexstring", type:"string", required:true},
                {name:"prevtxs", type:"json", required:false},
                {name:"privkeys", type:"json", required:false},
                {name:"sighashtype", type:"string", required:false}
              ]},
              "submitwork": { params: [
                {name:"data", type:"string", required:true},
                {name:"mask", type:"string", required:false}
              ]},
              "verifychain": { params: [
                {name:"checklevel", type:"number", required:true},
                {name:"numblocks", type:"number", required:true}
              ]},
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
                {name:"request (mode/address/data/longpollid)", type:"json", required:false}
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
            const $ = id => document.getElementById(id);
            const LOG_MAX = 500;
            let live = null;            // EventSource
            let fallbackTimer = null;
            let peersAll = [];          // last peer list (pushed or fetched)
            let gossipOnlyCount = 0;
            let showGossip = false;
            let gossipTimer = null;
            let logLines = [];          // {seq,t,lvl,m}
            let logLastSeq = 0;
            let logPaused = false;
            let logPending = [];
            let logNewWhileAway = 0;
            let heightSamples = [];     // [time, height] over the last ~30 s, for the sync rate
            let shutdownState = null;   // null | "running" | "complete" | "lost"
            let shutdownStartedAt = 0;
            let shutdownStep = "";

            function currentTheme() {
                const t = document.documentElement.getAttribute("data-theme");
                return t === "light" || t === "dark" ? t : "auto";
            }

            function applyTheme(t) {
                if (t === "auto") document.documentElement.removeAttribute("data-theme");
                else document.documentElement.setAttribute("data-theme", t);
                try { if (t === "auto") localStorage.removeItem("theme"); else localStorage.setItem("theme", t); } catch (e) { /* choice just won't be remembered */ }
                $("theme-btn").textContent = "Theme: " + t.charAt(0).toUpperCase() + t.slice(1);
            }

            document.addEventListener("DOMContentLoaded", () => {
                applyTheme(currentTheme());
                $("theme-btn").addEventListener("click", () => {
                    const order = ["auto", "light", "dark"];
                    applyTheme(order[(order.indexOf(currentTheme()) + 1) % 3]);
                });
                loadApiKey();
                loadConfig();
                $("config-form").addEventListener("submit", onSaveConfig);
                $("stop-node-btn").addEventListener("click", onStopNode);
                $("peers-toggle").addEventListener("click", onToggleGossip);
                setupLogControls();
                setupRpcPanel();
                connectLive();
                setInterval(tickBackoffs, 1000);
                setInterval(() => { if (shutdownState === "running") renderShutdown(); }, 1000);
            });

            /* ---- live connection ------------------------------------------------ */

            function setLive(state, text) {
                $("live").dataset.state = state;
                $("live-text").textContent = text;
            }

            function connectLive() {
                if (!window.EventSource) { startFallback(); return; }
                live = new EventSource("/api/events");
                live.onopen = () => { setLive("live", "Live"); stopFallback(); };
                live.onerror = () => {
                    if (shutdownState === "complete") return;          // the node announced it finished; nothing more to wait for
                    if (shutdownState === "running") { onShutdown({ phase: "lost" }); return; }
                    setLive("connecting", "Reconnecting");
                    startFallback();     // keep the page current while the stream is down; EventSource retries by itself
                };
                live.addEventListener("status", e => onStatus(JSON.parse(e.data)));
                live.addEventListener("peers", e => { const d = JSON.parse(e.data); gossipOnlyCount = d.gossipOnly; if (!showGossip) setPeers(d.peers); });
                live.addEventListener("mempool", e => onMempool(JSON.parse(e.data)));
                live.addEventListener("logs", e => { logLines = []; logLastSeq = 0; $("log").textContent = ""; JSON.parse(e.data).forEach(addLogLine); flushLog(true); });
                live.addEventListener("log", e => addLogLine(JSON.parse(e.data)));
                live.addEventListener("shutdown", e => onShutdown(JSON.parse(e.data)));
            }

            /* ---- shutdown banner ------------------------------------------------ */

            const STEP_TEXT = {
                "sync.stop": "stopping chain sync",
                "p2p.stop": "closing peer connections",
                "rpc.stop": "stopping the RPC server",
                "socketServer.stop": "stopping the local socket server",
                "db.commit": "saving the chain database",
                "db.markCleanShutdown": "marking a clean shutdown",
                "db.close": "closing the chain database (this can take a few minutes)",
                "ConfigDB.commit": "saving settings",
                "ConfigDB.close": "closing the settings database"
            };

            function onShutdown(d) {
                if (shutdownState === "complete") return;
                if (d.phase === "running") {
                    if (shutdownState !== "running") { shutdownStartedAt = d.startedAt || Date.now(); }
                    shutdownState = "running";
                    shutdownStep = d.step || "";
                } else if (d.phase === "complete") {
                    shutdownState = "complete";
                    if (live) { live.close(); live = null; }
                    stopFallback();
                    setLive("down", "Node stopped");
                    document.title = "Node stopped";
                } else if (d.phase === "lost") {
                    shutdownState = "lost";
                    if (live) { live.close(); live = null; }
                    stopFallback();
                    setLive("down", "Node not reachable");
                } else { return; }
                renderShutdown();
            }

            function renderShutdown() {
                const b = $("shutdown-banner");
                if (!shutdownState) { b.hidden = true; return; }
                b.hidden = false;
                if (shutdownState === "running") {
                    const secs = Math.max(0, Math.round((Date.now() - shutdownStartedAt) / 1000));
                    b.className = "banner warn";
                    $("shutdown-title").textContent = "The node is shutting down. Do not turn off the computer yet.";
                    $("shutdown-text").textContent = (STEP_TEXT[shutdownStep] ? "Now " + STEP_TEXT[shutdownStep] + ". " : "") + secs + " s elapsed.";
                } else if (shutdownState === "complete") {
                    b.className = "banner ok";
                    $("shutdown-title").textContent = "Shutdown complete.";
                    $("shutdown-text").textContent = "It is now safe to close this window or turn off the computer.";
                } else {
                    b.className = "banner bad";
                    $("shutdown-title").textContent = "Lost contact with the node during shutdown.";
                    $("shutdown-text").textContent = "Completion was not confirmed. Look for 'Shutdown complete' in the node's console window before turning off the computer.";
                }
            }

            function startFallback() {
                if (fallbackTimer) return;
                setLive("polling", "Polling");
                const poll = async () => {
                    try {
                        const sd = await (await fetch("/api/shutdown")).json();
                        if (sd.phase) onShutdown(sd);
                        onStatus(await (await fetch("/api/status")).json());
                        onMempool(await (await fetch("/api/mempool")).json());
                        if (!showGossip) {
                            const all = await (await fetch("/api/peertable")).json();
                            const split = splitPeers(all);
                            gossipOnlyCount = split.gossip.length;
                            setPeers(split.shown);
                        }
                        const lines = await (await fetch("/api/log")).json();
                        lines.forEach(addLogLine);
                        flushLog(false);
                    } catch (e) {
                        if (shutdownState === "running") onShutdown({ phase: "lost" });
                        else if (!shutdownState) setLive("down", "Node not reachable");
                    }
                };
                poll();
                fallbackTimer = setInterval(poll, 5000);
            }

            function stopFallback() {
                if (fallbackTimer) { clearInterval(fallbackTimer); fallbackTimer = null; }
            }

            /* ---- status: sync strip, gauges, banners ---------------------------- */

            function fmtNum(n) { return Number(n).toLocaleString("en-US"); }
            function gb(b) { return (b / 1073741824).toFixed(1); }

            function setGauge(tileId, pct, level) {
                const t = $(tileId);
                const p = Math.max(0, Math.min(100, pct));
                t.querySelector(".fill").setAttribute("stroke-dasharray", p.toFixed(1) + " 100");
                t.dataset.level = level || (p >= 90 ? "bad" : p >= 70 ? "warn" : "ok");
            }

            function onStatus(d) {
                $("version").textContent = d.version;
                $("uptime").textContent = d.uptime;
                $("block-height").textContent = fmtNum(d.blockHeight);

                // sync strip
                const now = Date.now();
                heightSamples.push([now, d.blockHeight]);
                while (heightSamples.length > 2 && now - heightSamples[0][0] > 30000) heightSamples.shift();
                const bar = $("sync-bar"), fill = $("sync-fill");
                if (d.syncPercent === null || !d.networkHeight) {
                    $("sync-percent").textContent = "...";
                    $("sync-note").textContent = "Waiting for peers";
                    fill.style.width = "0%";
                    bar.classList.remove("done");
                } else {
                    const behind = Math.max(0, d.networkHeight - d.blockHeight);
                    $("sync-percent").textContent = d.syncPercent + "%";
                    fill.style.width = d.syncPercent + "%";
                    bar.setAttribute("aria-valuenow", d.syncPercent);
                    bar.classList.toggle("done", behind <= 1);
                    if (behind <= 1) {
                        $("sync-note").textContent = "In sync with the network (height " + fmtNum(d.networkHeight) + ")";
                    } else {
                        const first = heightSamples[0], last = heightSamples[heightSamples.length - 1];
                        const secs = (last[0] - first[0]) / 1000;
                        const rate = secs >= 5 ? (last[1] - first[1]) / secs : 0;
                        let note = fmtNum(behind) + " blocks behind (network " + fmtNum(d.networkHeight) + ")";
                        if (rate > 0.05) note += " · " + rate.toFixed(1) + " blocks/s · about " + fmtEta(behind / rate) + " left";
                        $("sync-note").textContent = note;
                    }
                }

                // gauges
                const s = d.system;
                if (s) {
                    if (s.processCpu === null) {
                        $("cpu-val").textContent = "n/a"; $("cpu-sub").textContent = "";
                        setGauge("t-cpu", 0);
                    } else {
                        $("cpu-val").textContent = s.processCpu.toFixed(0) + "%";
                        $("cpu-sub").textContent = "machine " + (s.systemCpu === null ? "n/a" : s.systemCpu.toFixed(0) + "%");
                        setGauge("t-cpu", s.processCpu, s.processCpu >= 95 ? "warn" : "ok");
                    }
                    const heapPct = s.heapMax > 0 ? s.heapUsed * 100 / s.heapMax : 0;
                    $("mem-val").textContent = gb(s.heapUsed) + " GB";
                    $("mem-sub").textContent = "of " + gb(s.heapMax) + " GB heap";
                    $("t-mem").title = s.physTotal > 0 ? "Machine memory in use: " + gb(s.physTotal - s.physFree) + " of " + gb(s.physTotal) + " GB" : "";
                    setGauge("t-mem", heapPct);
                    const low = s.diskLevel !== "OK";
                    $("disk-banner").hidden = !low;
                    if (low) $("disk-banner-free").textContent = gb(s.diskUsable) + " GB";
                }

                renderStorage(d.storage, s);

                // halt banner
                if (d.halted) { $("halt-height").textContent = d.halted.height; $("halt-banner").hidden = false; }
                else { $("halt-banner").hidden = true; }
            }

            function fmtSize(b) {
                if (b >= 1073741824) return (b / 1073741824).toFixed(b >= 107374182400 ? 0 : 1) + " GB";
                if (b >= 1048576) return (b / 1048576).toFixed(b >= 104857600 ? 0 : 1) + " MB";
                if (b >= 1024) return (b / 1024).toFixed(0) + " KB";
                return b + " B";
            }

            function renderStorage(st, sys) {
                const bar = $("stor-bar"), legend = $("stor-legend");
                if (!st || st.free < 0 || st.total <= 0) { bar.innerHTML = ""; legend.textContent = "n/a"; return; }
                bar.setAttribute("data-level", sys && sys.diskLevel === "CRITICAL" ? "bad" : sys && sys.diskLevel === "LOW" ? "warn" : "ok");
                const node = Math.min(st.nodeBytes, st.total);
                const free = Math.min(st.free, st.total);
                const other = Math.max(0, st.total - free - node);        // System and Apps: everything else on the drive
                const pct = v => v * 100 / st.total;
                const parts = [
                    { id: "sys",  label: "System",              bytes: other, tip: "Everything else on this drive: the operating system, programs and other files" },
                    { id: "node", label: "Full Node",           bytes: node,  tip: "All of the node's files (chain database, snapshots, logs and scratch)" },
                    { id: "free", label: "Free Space",          bytes: free,  tip: "Free space on this drive" }
                ];
                let barHtml = "", legHtml = "";
                for (const g of parts) {
                    const tip = g.label + ": " + fmtSize(g.bytes) + " (" + pct(g.bytes).toFixed(1) + "% of the drive). " + g.tip;
                    barHtml += '<span style="flex-basis:' + pct(g.bytes).toFixed(3) + '%;background:var(--c-' + g.id + ')" title="' + escapeHtml(tip) + '"></span>';
                    legHtml += '<span title="' + escapeHtml(tip) + '"><i style="background:var(--c-' + g.id + ')"></i>' + escapeHtml(g.label)
                            + ' <b>' + fmtSize(g.bytes) + '</b> ' + pct(g.bytes).toFixed(pct(g.bytes) < 10 ? 1 : 0) + '%</span>';
                }
                bar.innerHTML = barHtml;
                legend.innerHTML = legHtml;
                bar.setAttribute("aria-label", "Drive use: system " + fmtSize(other) + ", full node " + fmtSize(node) + ", free " + fmtSize(free));
            }

            function fmtEta(sec) {
                if (sec < 90) return Math.round(sec) + " s";
                if (sec < 5400) return Math.round(sec / 60) + " min";
                if (sec < 172800) return (sec / 3600).toFixed(1) + " h";
                return (sec / 86400).toFixed(1) + " days";
            }

            function onMempool(d) {
                $("mempool-count").textContent = fmtNum(d.count);
                $("mempool-bytes").textContent = formatBytes(d.bytes) + " of " + formatBytes(d.maxBytes);
                $("t-pool").title = "Minimum relay fee: " + (d.minRelayFeeRate / 1000000) + " HNS/kB";
                const pct = d.maxBytes > 0 ? d.bytes * 100 / d.maxBytes : 0;
                $("mempool-fill").style.width = Math.max(pct > 0 ? 1 : 0, pct) + "%";
            }

            /* ---- peers ---------------------------------------------------------- */

            function isVerified(p) { return p.state === "connected" || p.successes > 0 || p.seed; }
            function isGossipOnly(p) { return !isVerified(p) && p.state !== "backoff" && p.state !== "banned" && p.state !== "blacklisted"; }
            function splitPeers(all) {
                return { shown: all.filter(p => !isGossipOnly(p)), gossip: all.filter(isGossipOnly) };
            }

            function setPeers(list) {
                peersAll = list;
                renderPeers();
            }

            function renderPeers() {
                const tbody = document.querySelector("#peertable tbody");
                const count = st => peersAll.filter(p => p.state === st).length;
                const chips = [];
                chips.push('<span class="chip ok">' + count("connected") + ' connected</span>');
                if (count("backoff")) chips.push('<span class="chip warn">' + count("backoff") + ' backed off</span>');
                if (count("banned")) chips.push('<span class="chip bad">' + count("banned") + ' banned</span>');
                $("peers-chips").innerHTML = chips.join("");
                $("peers-summary").textContent = peersAll.filter(isVerified).length + " verified peers";
                $("peers-toggle").textContent = (showGossip ? "Hide " : "Show ") + fmtNum(gossipOnlyCount) + " unverified addresses";
                if (peersAll.length === 0) { tbody.innerHTML = '<tr><td colspan="3">No peers to show yet.</td></tr>'; return; }
                const sorted = peersAll.slice().sort((a, b) => (b.score - a.score) || a.ip.localeCompare(b.ip));
                tbody.innerHTML = sorted.map(p => `
                    <tr title="${escapeHtml(tooltipFor(p))}">
                        <td>${escapeHtml(p.ip)}${p.seed ? " &#9733;" : ""}
                            <span class="sub">${escapeHtml(p.agent || (p.label || p.source || ""))}${p.height ? " &middot; " + fmtNum(p.height) : ""}</span></td>
                        <td>${pillFor(p)}${p.state === "banned"
                            ? ' <button class="unban-btn" data-ip="' + escapeHtml(p.ip) + '">Unban</button>'
                                + '<span class="sub">' + escapeHtml(p.banReason || "") + '</span>'
                            : ""}</td>
                        <td><span class="score ${scoreClass(p.score)}"><i style="--w:${Math.max(0, Math.min(100, p.score))}%"></i>${p.score}</span></td>
                    </tr>`).join("");
                tbody.querySelectorAll(".unban-btn").forEach(btn => btn.addEventListener("click", () => onUnban(btn.dataset.ip)));
                tickBackoffs();
            }

            function backoffMsOf(p) {
                return p.backoffMs !== undefined ? p.backoffMs : Math.max(0, p.backoffUntil - Date.now());
            }

            function tickBackoffs() {
                document.querySelectorAll("[data-until]").forEach(el => {
                    el.textContent = "Backoff " + fmtDur(Math.max(0, Number(el.dataset.until) - Date.now()));
                });
            }

            async function onToggleGossip() {
                showGossip = !showGossip;
                if (showGossip) {
                    await refreshAllPeers();
                    gossipTimer = setInterval(refreshAllPeers, 5000);
                } else {
                    clearInterval(gossipTimer);
                    gossipTimer = null;
                    try { setPeers(splitPeers(await (await fetch("/api/peertable")).json()).shown); } catch (e) { /* next push fixes it */ }
                }
            }

            async function refreshAllPeers() {
                try {
                    const all = await (await fetch("/api/peertable")).json();
                    gossipOnlyCount = all.filter(isGossipOnly).length;
                    setPeers(all);
                } catch (e) { /* retry on the next tick */ }
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

            function scoreClass(n) { return n >= 70 ? "score-high" : (n >= 40 ? "score-mid" : "score-low"); }

            function pillFor(p) {
                switch (p.state) {
                    case "banned": return '<span class="pill banned">Banned</span>';
                    case "connected":
                        return '<span class="pill connected">Connected &middot; ' + escapeHtml(p.direction)
                            + (p.transport === "plain" ? ' &middot; cleartext' : '') + '</span>';
                    case "blacklisted": return '<span class="pill blacklisted">Blacklisted</span>';
                    case "backoff":
                        return '<span class="pill backoff" data-until="' + (p.backoffUntil !== undefined ? p.backoffUntil : Date.now() + p.backoffMs)
                            + '">Backoff ' + fmtDur(backoffMsOf(p)) + '</span>';
                    case "plain": return '<span class="pill plain">Cleartext</span>';
                    default: return '<span class="pill idle" title="Known peer with a key; no open connection right now">Not connected</span>';
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
                if (p.state === "idle" && p.score < 25) {
                    lines.push("not being dialed normally: score " + p.score + " is under the 25 dial floor (test dial every 10 min if it has worked before)");
                }
                if (p.penalties && p.penalties.length) {
                    lines.push("recent penalties (this run):");
                    p.penalties.forEach(x => lines.push("  " + x));
                }
                if (p.state === "banned") lines.push("ban reason: " + (p.banReason || ""));
                return lines.join(String.fromCharCode(10));
            }

            async function onUnban(ip) {
                try {
                    await fetch("/api/bans/unban", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ ip }) });
                    if (showGossip) refreshAllPeers();   // otherwise the next push shows the change
                } catch (e) { /* the next update shows the real state */ }
            }

            /* ---- live log ------------------------------------------------------- */

            function setupLogControls() {
                const log = $("log");
                $("log-filter").addEventListener("input", () => renderLog());
                $("log-errors").addEventListener("change", () => renderLog());
                $("log-pause").addEventListener("click", () => {
                    logPaused = !logPaused;
                    $("log-pause").textContent = logPaused ? "Resume" : "Pause";
                    if (!logPaused) { logPending.forEach(l => pushLine(l)); logPending = []; renderLog(); }
                });
                $("log-copy").addEventListener("click", async () => {
                    const text = visibleLines().map(l => fmtLogLine(l)).join(String.fromCharCode(10));
                    try { await navigator.clipboard.writeText(text); $("log-copy").textContent = "Copied"; }
                    catch (e) { $("log-copy").textContent = "Copy failed"; }
                    setTimeout(() => { $("log-copy").textContent = "Copy"; }, 1500);
                });
                $("log-jump").addEventListener("click", () => { log.scrollTop = log.scrollHeight; logNewWhileAway = 0; $("log-jump").hidden = true; });
                log.addEventListener("scroll", () => { if (atBottom()) { logNewWhileAway = 0; $("log-jump").hidden = true; } });
            }

            function atBottom() { const l = $("log"); return l.scrollHeight - l.scrollTop - l.clientHeight < 24; }

            function pushLine(l) {
                logLines.push(l);
                if (logLines.length > LOG_MAX) logLines.shift();
            }

            function addLogLine(l) {
                if (l.seq <= logLastSeq) return;      // already shown (backlog overlap, or the fallback re-reading)
                logLastSeq = l.seq;
                if (logPaused) { logPending.push(l); if (logPending.length > LOG_MAX) logPending.shift(); return; }
                pushLine(l);
                scheduleLogRender();
            }

            let logRenderQueued = false;
            function scheduleLogRender() {
                if (logRenderQueued) return;
                logRenderQueued = true;
                requestAnimationFrame(() => { logRenderQueued = false; flushLog(false); });
            }

            function flushLog(forceBottom) { renderLog(forceBottom); }

            function visibleLines() {
                const q = $("log-filter").value.trim().toLowerCase();
                const errOnly = $("log-errors").checked;
                return logLines.filter(l => (!errOnly || l.lvl === "err") && (q === "" || l.m.toLowerCase().indexOf(q) >= 0));
            }

            function fmtLogLine(l) {
                return new Date(l.t).toTimeString().slice(0, 8) + "  " + l.m;
            }

            function renderLog(forceBottom) {
                const log = $("log");
                const stick = forceBottom || atBottom();
                const lines = visibleLines();
                const before = log.childElementCount;
                const html = lines.map(l => {
                    let m = escapeHtml(l.m), tag = "";
                    if (l.m.charAt(0) === "[") {
                        const end = l.m.indexOf("]");
                        if (end > 0 && end < 40) { tag = escapeHtml(l.m.slice(0, end + 1)); m = escapeHtml(l.m.slice(end + 1)); }
                    }
                    return '<div class="ln' + (l.lvl === "err" ? " err" : "") + '"><time>' + new Date(l.t).toTimeString().slice(0, 8)
                        + '</time>' + (tag ? '<span class="tg">' + tag + '</span>' : "") + m + '</div>';
                }).join("");
                const prevTop = log.scrollTop;
                log.innerHTML = html;
                if (stick) { log.scrollTop = log.scrollHeight; }
                else {
                    log.scrollTop = prevTop;
                    const added = Math.max(0, log.childElementCount - before);
                    if (added > 0) { logNewWhileAway += added; $("log-jump").textContent = logNewWhileAway + " new lines - jump to latest"; $("log-jump").hidden = false; }
                }
            }

            /* ---- settings, access, stop ---------------------------------------- */

            async function onStopNode() {
                if (!confirm("Stop the node? This will shut it down gracefully.")) return;
                const message = $("stop-message");
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

            // Escapes all five HTML-significant characters (quotes too, for attribute context).
            function escapeHtml(s) {
                return String(s == null ? "" : s)
                    .replace(/&/g, "&amp;")
                    .replace(/</g, "&lt;")
                    .replace(/>/g, "&gt;")
                    .replace(/"/g, "&quot;")
                    .replace(/'/g, "&#39;");
            }

            async function loadApiKey() {
                const el = $("api-key");
                try {
                    const data = await (await fetch("/api/apikey")).json();
                    el.textContent = data.apiKey && data.apiKey.length > 0 ? data.apiKey : "(none set)";
                } catch (e) { el.textContent = "Failed to load."; }
            }

            async function loadConfig() {
                const form = $("config-form");
                try {
                    const data = await (await fetch("/api/config")).json();
                    form.elements["rpc.host"].value = data["rpc.host"];
                    form.elements["miner.address"].value = data["miner.address"] || "";
                } catch (e) {
                    $("config-message").textContent = "Failed to load current configuration.";
                    $("config-message").className = "error";
                }
            }

            /* ---- RPC console --------------------------------------------------- */

            function setupRpcPanel() {
                const select = document.getElementById("rpc-method-select");
                const names = Object.keys(RPC_METHODS).sort();
                select.innerHTML = names.map(n => `<option value="${n}">${n}</option>`).join("");
                select.addEventListener("change", () => renderRpcForm(select.value));
                renderRpcForm(select.value);

                $("rpc-form").addEventListener("submit", onSubmitRpc);
            }

            function renderRpcForm(methodName) {
                const form = $("rpc-form");
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

            async function onSaveConfig(event) {
                event.preventDefault();
                const form = event.target;
                const message = document.getElementById("config-message");
                message.textContent = "";
                message.className = "";

                const payload = {
                    "rpc.host": form.elements["rpc.host"].value,
                    "miner.address": form.elements["miner.address"].value
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
            """ + RPC_METHODS_JS;
}
