# SPDX-License-Identifier: Apache-2.0
"""Default web control panel for the AlgoVoi Secure Hub.

A single self-contained HTML page (no build step, no external assets) that renders
the live posture: every bridged service + its health/attributes, the issuer trust
set, the policy-bridge status (active policy_ref), and the audit depth. Server-side
rendered from the data the control plane already holds; meta-refreshes for a live
monitor feel. Read-only — admin actions stay behind the bearer token on the API.
"""
from __future__ import annotations

import html


_CSS = """
:root{--bg:#0a0e17;--card:#111827;--line:#1e2a3a;--fg:#f1f5f9;--mut:#94a3b8;--ok:#10b981;--bad:#ef4444;--accent:#3b82f6;--ok-bg:rgba(16,185,129,.08);--bad-bg:rgba(239,68,68,.08)}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.6 system-ui,-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif}
.mono,code{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px}
.topbar{background:var(--card);border-bottom:1px solid var(--line);padding:0 32px;display:flex;align-items:center;gap:12px;height:52px;position:sticky;top:0;z-index:10}
.tb-brand{font-size:15px;font-weight:600;letter-spacing:-.015em}.tb-dim{color:var(--mut);font-weight:400}
.tb-ver{color:var(--mut);font-size:12px;background:rgba(255,255,255,.05);padding:2px 8px;border-radius:6px}
.tb-spacer{flex:1}.tb-dot{width:8px;height:8px;border-radius:50%;flex-shrink:0}
.tb-dot.ok{background:var(--ok);box-shadow:0 0 0 3px var(--ok-bg)}
.tb-dot.err{background:var(--bad);box-shadow:0 0 0 3px var(--bad-bg)}
.tb-msg{font-size:12px;color:var(--mut)}
.wrap{max-width:1120px;margin:0 auto;padding:28px 24px 60px}
.sub{color:var(--mut);font-size:12px;margin-bottom:24px}
.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:24px}
.stat{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:18px 20px;box-shadow:0 1px 3px rgba(0,0,0,.4)}
.stat .n{font-size:28px;font-weight:700;letter-spacing:-.025em;line-height:1.1}
.stat .l{color:var(--mut);font-size:11px;text-transform:uppercase;letter-spacing:.08em;margin-top:5px}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:20px;margin-bottom:16px;box-shadow:0 1px 3px rgba(0,0,0,.4)}
.card h2{font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.1em;color:var(--mut);margin:0 0 16px;padding-bottom:12px;border-bottom:1px solid var(--line)}
table{width:100%;border-collapse:collapse}
th{color:var(--mut);font-weight:500;font-size:11px;text-transform:uppercase;letter-spacing:.06em;padding:0 10px 10px;text-align:left}
td{padding:10px;font-size:13px;border-bottom:1px solid rgba(30,42,58,.6);vertical-align:top}
tr:last-child td{border-bottom:none}tr:hover td{background:rgba(255,255,255,.02)}
.badge{display:inline-flex;align-items:center;gap:5px;padding:3px 10px;border-radius:20px;font-size:11px;font-weight:600}
.up{background:var(--ok-bg);color:var(--ok)}.down{background:var(--bad-bg);color:var(--bad)}
.badge.up::before,.badge.down::before{content:'';width:5px;height:5px;border-radius:50%;background:currentColor;flex-shrink:0}
.mono{color:var(--accent);word-break:break-all}.mut{color:var(--mut)}
.foot{color:var(--mut);font-size:12px;padding-top:16px;border-top:1px solid var(--line)}
.foot a{color:var(--mut);text-decoration:none}.foot a:hover{color:var(--fg)}
.ks-btn{display:inline-flex;align-items:center;gap:6px;padding:6px 14px;background:rgba(59,130,246,.08);color:var(--accent);border:1px solid rgba(59,130,246,.22);border-radius:8px;font:500 13px system-ui,sans-serif;text-decoration:none;transition:background .15s,border-color .15s;white-space:nowrap}
.ks-btn:hover{background:rgba(59,130,246,.16);border-color:rgba(59,130,246,.4);color:var(--accent)}
"""


def _badge(up: bool) -> str:
    return '<span class="badge up">UP</span>' if up else '<span class="badge down">DOWN</span>'


def render_login(*, error: bool = False) -> str:
    """Themed sign-in page (same palette as the control panel). Password = the admin token."""
    msg = '<p class="err">Incorrect token — try again.</p>' if error else ''
    return f"""<!doctype html><html lang=en><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>Sign in — AlgoVoi Secure Hub</title><style>{_CSS}
.login{{max-width:380px;margin:14vh auto}}
.login .card{{padding:28px}}
.login .brand{{font-size:16px;font-weight:600;margin-bottom:3px}}
.login .tagline{{color:var(--mut);font-size:12px;margin-bottom:22px}}
input[type=password]{{width:100%;padding:11px 13px;background:var(--bg);border:1px solid var(--line);
border-radius:8px;color:var(--fg);font:14px system-ui,sans-serif;margin:6px 0 14px;
outline:none;transition:border-color .15s}}
input[type=password]:focus{{border-color:var(--accent)}}
button{{width:100%;padding:11px;background:var(--accent);color:#fff;border:0;border-radius:8px;
font:600 14px system-ui,sans-serif;cursor:pointer;transition:opacity .15s}}
button:hover{{opacity:.88}}.err{{color:var(--bad);font-size:12px;margin-top:8px}}
</style></head><body>
<div class=topbar><span class=tb-brand>AlgoVoi <span class=tb-dim>Substrate-2</span></span></div>
<div class=wrap><div class=login><div class=card>
<div class=brand>Control plane</div>
<div class=tagline>Sign in with your admin token to continue.</div>
<form method=post action="/login">
<input type=password name=password placeholder="Admin token" autofocus autocomplete=current-password>
<button type=submit>Sign in</button>{msg}</form>
</div></div></div></body></html>"""


def render_panel(*, version: str, issuers: list[dict], services: list[dict],
                substrates: list[dict], audit_entries: int, policy: dict, all_up: bool,
                keystone_steps: list[dict] | None = None) -> str:
    e = html.escape
    targets = [*services, *substrates]
    up_n = sum(1 for target in targets if target.get("up"))
    svc_rows = "".join(
        f"<tr><td>{e(s['name'])}</td><td class='mut'>{e(str(s.get('type','')))}</td>"
        f"<td class='mono'>{e(str(s.get('url','')))}</td><td>{_badge(bool(s.get('up')))}</td>"
        f"<td class='mut'>{e(str(s.get('detail',''))[:80])}</td></tr>"
        for s in services
    ) or "<tr><td colspan=5 class='mut'>no services registered — POST /v1/services to bridge one</td></tr>"
    sub_rows = "".join(
        f"<tr><td>{e(s['name'])}</td><td>{e(str(s.get('family','')))}</td>"
        f"<td>{e(str(s.get('version','')))}</td><td>{e(str(s.get('adapter','')))}</td>"
        f"<td>{_badge(bool(s.get('up')))}</td><td class='mut'>{e(', '.join(s.get('capabilities', [])))}</td></tr>"
        for s in substrates
    ) or "<tr><td colspan=6 class='mut'>no substrates registered — POST /v1/substrates to attach one</td></tr>"
    iss_rows = "".join(
        f"<tr><td>{e(i['did'])}</td><td class='mono'>{e(i['kid'])}</td><td class='mut'>{e(str(i.get('added_at','')))}</td></tr>"
        for i in issuers
    ) or "<tr><td colspan=3 class='mut'>no issuers registered</td></tr>"

    if policy.get("active"):
        pol = (f"<table><tr><th>status</th><td><span class='badge up'>ACTIVE</span></td></tr>"
               f"<tr><th>policy</th><td>{e(str(policy.get('label','')))}</td></tr>"
               f"<tr><th>policy_ref</th><td class='mono'>{e(policy.get('policy_ref',''))}</td></tr>"
               f"<tr><th>bound</th><td class='mut'>{e(str(policy.get('bound_count',0)))} subject(s) bound this session</td></tr>"
               f"<tr><th>spec</th><td class='mut'>draft-hopley-x402-retention-chain-04 §7.7 · substrate2.policy_binding</td></tr></table>")
    else:
        pol = ("<p class='mut'>Policy bridge is built-in and ready. No active policy set — "
               "POST a policy document to <code>/v1/policy</code> (admin) to seal records under a "
               "content-addressed <code>policy_ref</code> and make silent rotation detectable.</p>")

    if keystone_steps:
        _org = '<span class="badge up">org</span>'
        _def = '<span class="mut">default</span>'
        ks_rows = ""
        for s in keystone_steps:
            src = _org if s.get("settings_source") == "org" else _def
            sref = e(str(s.get("active_settings_ref", "")))
            ks_rows += (
                f"<tr><td class='mut'>{e(str(s['order']))}</td><td>{e(s['step'])}</td>"
                f"<td class='mono'>{e(s['ref_emitted'])}</td><td class='mut'>{e(s['posture'])}</td>"
                f"<td>{src}</td><td class='mut'>v{e(str(s['settings_version']))}</td>"
                f"<td class='mono' title='{sref}'>{sref[:18]}...</td></tr>")
        ks_card = (
            "<div class=card><h2>Keystone control · per-step settings</h2><table>"
            "<tr><th>#</th><th>step</th><th>emits</th><th>posture</th><th>source</th><th>ver</th><th>settings_ref</th></tr>"
            f"{ks_rows}</table>"
            "<div class=foot style='display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:10px'>"
            "<span>Self-hosted. Settings tune the verdict, never the hash.</span>"
            "<a href='/v1/keystone/panel' class=ks-btn>Tune settings ↗</a>"
            "</div></div>")
    else:
        ks_card = ""

    dot_cls = "ok" if (all_up or not targets) else "err"
    status_txt = ("All systems operational" if all_up and targets
                  else "Ready" if not targets else "Service degraded")
    return f"""<!doctype html><html lang=en><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1"><meta http-equiv=refresh content=10>
<title>AlgoVoi Secure Hub</title><style>{_CSS}</style></head><body>
<div class=topbar>
  <span class=tb-brand>AlgoVoi <span class=tb-dim>Substrate-2</span></span>
  <span class=tb-ver>v{e(version)}</span>
  <span class=tb-spacer></span>
  <div class="tb-dot {dot_cls}"></div>
  <span class=tb-msg>{status_txt}</span>
</div>
<div class=wrap>
<div class=sub>Control plane · live posture across the federation · ZK-proof · ATB · policy bridge · auto-refresh 10s</div>
<div class=grid>
  <div class=stat><div class=n>{len(services)}</div><div class=l>Services</div></div>
  <div class=stat><div class=n>{up_n}/{len(targets)}</div><div class=l>Healthy targets</div></div>
  <div class=stat><div class=n>{len(issuers)}</div><div class=l>Issuers</div></div>
  <div class=stat><div class=n>{audit_entries}</div><div class=l>Audit entries</div></div>
</div>
<div class=card><h2>Policy bridge</h2>{pol}</div>
<div class=card><h2>Substrates &amp; adapters</h2><table>
<tr><th>name</th><th>family</th><th>version</th><th>adapter</th><th>health</th><th>capabilities</th></tr>{sub_rows}</table></div>
<div class=card><h2>Services &amp; attributes</h2><table>
<tr><th>name</th><th>type</th><th>url</th><th>health</th><th>detail</th></tr>{svc_rows}</table></div>
<div class=card><h2>Issuer trust set</h2><table>
<tr><th>did</th><th>kid</th><th>added_at</th></tr>{iss_rows}</table></div>
{ks_card}
<div class=foot>Read-only view. Admin actions require the bearer token on the API. · <a href="/docs">API docs</a> · <a href="/logout">Sign out</a></div>
</div></body></html>"""
