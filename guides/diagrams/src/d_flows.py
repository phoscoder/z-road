from svg import *


def roles_and_access():
    s = Svg(960, 640, "Operators, roles and the citizen lane",
            "Auditor, operator and admin form a ladder; the portal role is a separate lane that only reaches the citizen endpoint. Every privileged action is logged first.",
            "Who may do what", "Named people with their own tokens. Citizens are never given one.")
    # how it works
    s.rect(40, 96, 600, 96, "#FFFFFF", GREEN_BD, r=14)
    s.text(58, 122, "How it works", 13, 700, INK)
    s.lines(58, 144, ["• Every person has their own token. Only its hash is stored in a config file.", "• Failed logins are slowed down; removing an operator takes effect straight away.", "• The role decides what a token may do. The ladder grows to the right."], 12, 17, MUTED)
    # ladder
    xs = [40, 240, 440]
    ys = [380, 300, 220]
    bottom = 566
    for i, (name, role, items, kind) in enumerate(zip(["Auditor", "Operator", "Admin"], ["read only", "changes state", "everything"], [
        ["Audit log status", "Stored proofs", "Look up a subject (logged)", "Certificate status"],
        ["All an auditor can, plus:", "Refresh the directory", "Anchor the log, renew", "Republish services", "Register members*"],
        ["All an operator can, plus:", "Revoke members*"]], ["white", "soft", "green"])):
        x, y = xs[i], ys[i]
        h = bottom - y
        bg, bd, t1, t2 = {"white": ("#fff", "#C9D3CC", INK, MUTED), "soft": (GREEN_BG, GREEN_BD, GREEN_DK, "#4C7A62"), "green": (GREEN, GREEN, "#fff", "#CFE9DA")}[kind]
        s.rect(x, y, 190, h, bg, bd, r=14, shadow=True)
        s.text(x + 16, y + 28, name, 16, 700, t1)
        s.text(x + 16, y + 46, role, 11.5, 400, t2)
        for j, it in enumerate(items):
            s.text(x + 16, y + 70 + j * 17, "• " + it, 11.5, 400, t1 if kind == "green" else INK)
    s.text(450, 560, "* central server only", 11, 400, "#CFE9DA", italic=True)
    # portal lane
    s.rect(670, 96, 260, 470, BLUE_BG, BLUE_BD, r=16, dash="6 4", op=0.7)
    s.text(688, 122, "SEPARATE LANE", 10.5, 700, BLUE_TX, spacing="1.2")
    s.card(690, 142, 220, 78, "Portal", "a citizen-facing web service", "blue")
    s.lines(690, 252, ["Can use only:", "GET /citizen/v1/access-log", "and only with a valid", "identity assertion for the", "person who is logged in."], 11.5, 17, BLUE_TX)
    s.rect(690, 372, 220, 112, "#FFFFFF", RED_BD, r=12)
    s.text(704, 396, "Cannot", 12, 700, RED_TX)
    s.lines(704, 416, ["× touch any admin endpoint", "× choose whose record to read", "× act as an operator"], 11.5, 18, RED_TX)
    # bottom banner
    s.rect(40, 584, 890, 40, GOLD_BG, GOLD_BD, r=12)
    s.text(485, 609, "Every privileged action is written to the tamper-evident log before it runs. If it cannot be logged, it is not done.", 12.5, 600, GOLD_TX, "middle")
    return s


def citizen_flow():
    s = Svg(960, 510, "How a citizen sees who looked at their data",
            "The citizen logs in to the provider's own system, which issues a short-lived signed assertion. The portal passes it to the security server, which answers only for the identifier inside it.",
            "Citizen view: who looked at my record?", "The portal never chooses whose record to read.")
    s.card(30, 120, 150, 80, "Citizen", "opens the portal", "blue")
    s.card(230, 120, 170, 80, "Login system", "e.g. ZIMRA e-services", "gold", "proves who they are")
    s.card(450, 120, 150, 80, "Portal", "holds a portal token", "blue")
    s.card(650, 120, 140, 80, "Security server", "provider", "green")
    s.card(820, 120, 110, 80, "Audit log", "who, when, what", "white")
    s.badge(205, 100, 1, GOLD_BD, GOLD_TX)
    s.badge(425, 100, 2, GOLD_BD, GOLD_TX)
    s.badge(625, 100, 3)
    s.badge(805, 100, 4)
    s.line(180, 160, 230, 160, BLUE_TX, 2, arrow="end")
    s.line(400, 160, 450, 160, GOLD_BD, 2, arrow="end")
    s.line(600, 160, 650, 160, BLUE_TX, 2, arrow="end")
    s.line(790, 160, 820, 160, MUTED, 2, arrow="end")
    # explanations
    s.text(205, 232, "1  The citizen logs in", 12.5, 700, GOLD_TX, "middle")
    s.text(205, 250, "the way they already do", 11.5, 400, MUTED, "middle")
    s.text(425, 232, "2  An assertion is issued", 12.5, 700, GOLD_TX, "middle")
    s.text(425, 250, "signed, for this provider,", 11.5, 400, MUTED, "middle")
    s.text(425, 266, "valid for at most 10 minutes", 11.5, 400, MUTED, "middle")
    s.text(655, 232, "3  The portal asks", 12.5, 700, GREEN, "middle")
    s.text(655, 250, "portal token + assertion", 11.5, 400, MUTED, "middle")
    s.text(655, 266, "(no subject parameter)", 11.5, 400, MUTED, "middle")
    s.text(840, 232, "4  The lookup is", 12.5, 700, INK, "middle")
    s.text(840, 250, "recorded (keyed hash,", 11.5, 400, MUTED, "middle")
    s.text(840, 266, "never the identifier)", 11.5, 400, MUTED, "middle")
    # checks
    s.rect(30, 300, 900, 186, "#FFFFFF", GREEN_BD, r=14)
    s.text(50, 326, "The security server checks, in order", 13, 700, INK)
    checks = [
        "The token belongs to an operator with the portal role",
        "The assertion is signed by a trusted issuer (no unknown key)",
        "It was issued for this provider, is not expired and lasts no more than 10 minutes",
        "It is not forged: change one character of the identifier and the signature breaks",
    ]
    for i, c in enumerate(checks):
        s.badge(60, 352 + i * 26, i + 1, GREEN_BG, GREEN, 10)
        s.text(80, 357 + i * 26, c, 12, 400, INK)
    s.text(50, 468, "Then it returns that person's lookups only: who looked, when, for which service, and the result.", 12, 600, GREEN)
    return s


def hosted_member():
    s = Svg(960, 560, "A hosted member keeps its own key",
            "A vendor's shared node carries traffic for small members, but each member signs with its own key in a signer service on its own machine.",
            "Shared node with member-held keys", "The node can carry a member's traffic. It cannot make the member say something.")
    s.zone(30, 90, 470, 390, "The vendor's shared node", "grey")
    s.card(50, 130, 200, 90, "Security server", "the node's own identity", "green", "TLS to peers")
    s.card(270, 130, 210, 90, "Hosted member A", "own audit log, tokens, rules", "white")
    s.card(270, 240, 210, 90, "Hosted member B", "own audit log, tokens, rules", "white")
    s.text(60, 262, "Holds:", 12, 700, INK)
    s.lines(60, 282, ["• the node's certificate", "• each member's certificate", "  (public)"], 11.5, 17, MUTED)
    s.text(60, 352, "Never holds:", 12, 700, RED_TX)
    s.lines(60, 372, ["× any hosted member's", "  private key"], 11.5, 17, RED_TX)
    s.line(250, 175, 270, 175, MUTED, 1.8, arrow="end")
    s.path("M 250,200 L 262,200 L 262,285 L 270,285", MUTED, 1.8, arrow="end")
    # member machines
    s.zone(540, 90, 390, 390, "Each member's own machine", "soft")
    s.card(560, 130, 350, 100, "Signer service A", "holds member A's private key", "soft", "signs only A's own messages")
    s.card(560, 250, 350, 100, "Signer service B", "holds member B's private key", "soft", "signs only B's own messages")
    s.rect(560, 372, 350, 88, "#FFFFFF", GREEN_BD, r=12)
    s.text(576, 396, "The signer checks before signing", 12, 700, GREEN)
    s.lines(576, 415, ["✓ only for the node it is set up for", "✓ only this member's own requests and answers", "✓ writes its own audit log first, then signs"], 11.5, 16, INK)
    s.line(480, 175, 560, 175, GREEN, 2.6, arrow="both")
    s.line(480, 285, 560, 285, GREEN, 2.6, arrow="both")
    s.rect(494, 155, 62, 20, GREEN, "none", r=10, sw=0)
    s.text(525, 169, "sign this", 10.5, 700, "#fff", "middle")
    # bottom
    s.rect(30, 498, 900, 48, GOLD_BG, GOLD_BD, r=12)
    s.text(480, 520, "Peers accept a hosted member only from its node, and verify every message with the member's own key.", 12.5, 600, GOLD_TX, "middle")
    s.text(480, 537, "A hosted member cannot bypass its node. Revoke the node and everything it hosts is cut off.", 12, 400, "#8A6D00", "middle")
    return s


def rotation_timeline():
    s = Svg(960, 500, "Certificate rotation without dropped calls",
            "A new certificate is first listed and only later used, so peers have learned it before it appears. The previous certificate is accepted for a grace period and then retired.",
            "Rotation without dropped calls", "Two phases: announce the new certificate, then switch to it.")
    x0, x1 = 90, 900
    y = 120
    # axis
    s.line(x0, y + 250, x1, y + 250, LINE, 2)
    marks = [(x0, "t = 0", "renewed"), (x0 + 220, "+65 s", "switch"), (x0 + 600, "+10 min", "old retired")]
    for x, a, b in marks:
        s.line(x, y + 242, x, y + 258, INK, 2)
        s.text(x, y + 276, a, 12.5, 700, INK, "middle")
        s.text(x, y + 293, b, 11.5, 400, MUTED, "middle")
    # lanes
    lanes = [
        ("The central directory lists", [(x0, x1, "new certificate (current)  ·  old certificate kept in history", GREEN_BG, GREEN)]),
        ("The member presents", [(x0, x0 + 220, "old certificate", GOLD_BG, GOLD_TX), (x0 + 220, x1, "new certificate", GREEN_BG, GREEN)]),
        ("Peers accept", [(x0, x0 + 600, "old and new", BLUE_BG, BLUE_TX), (x0 + 600, x1, "new only", GREEN_BG, GREEN)]),
    ]
    ly = y - 6
    for name, segs in lanes:
        s.text(x0, ly - 4, name, 12, 700, INK)
        for a, b, label, bg, tx in segs:
            s.rect(a, ly + 4, b - a, 38, bg, "none", r=10, sw=0)
            s.text((a + b) / 2, ly + 28, label, 12, 600, tx, "middle")
        ly += 78
    # annotations
    s.rect(x0 + 8, y + 316 - 6, 800, 36, "#FFFFFF", GREEN_BD, r=10)
    s.text(x0 + 408, y + 339, "Defaults: switch after 65 s (2 × directory refresh + 5)  ·  grace 600 s  ·  renew 30 days before expiry", 12, 600, INK, "middle")
    return s


def sdk_layers():
    s = Svg(960, 490, "Where an SDK fits",
            "An SDK wraps the security server's plain HTTP API. It never signs, never holds keys and never speaks mutual TLS.",
            "Where an SDK fits", "Your application, the SDK, your own security server, then the network.")
    cols = [(30, "Your application", "ERP · portal · app", "white"), (250, "SDK", "this is the part you build", "green"), (470, "Your security server", "private HTTP listener", "soft"), (690, "Other members", "over mutual TLS", "white")]
    for x, t, sub, kind in cols:
        s.card(x, 100, 200, 84, t, sub, kind)
    for x in (230, 450, 670):
        s.line(x, 142, x + 20, 142, GREEN, 2.4, arrow="end")
    s.text(240, 214, "typed calls", 11, 400, MUTED, "middle", italic=True)
    s.text(460, 214, "plain HTTP", 11, 400, MUTED, "middle", italic=True)
    s.text(680, 214, "signed, mTLS", 11, 400, MUTED, "middle", italic=True)
    s.rect(30, 236, 450, 226, GREEN_BG, GREEN_BD, r=16)
    s.text(50, 262, "THE SDK DOES", 10.5, 700, GREEN, spacing="1.2")
    for i, t in enumerate(["Builds the call: path, Z-Road-Client, subject, content type", "Tells Z-Road's errors from the provider's own answers", "Gives each error a stable code and a retryable flag", "Queues work for outages: submit, poll, wait", "Hands back the proof, and verifies it if asked", "Supports shared nodes and tokens"]):
        s.text(52, 290 + i * 28, "✓  " + t, 12.5, 400, INK)
    s.rect(500, 236, 430, 226, RED_BG, RED_BD, r=16)
    s.text(520, 262, "THE SDK NEVER", 10.5, 700, RED_TX, spacing="1.2")
    for i, t in enumerate(["Signs messages or holds a private key", "Speaks mutual TLS to other members", "Looks up other members or their certificates", "Decides who may use a service", "Stores the audit log", "Retries blindly: it keeps the message id"]):
        s.text(522, 290 + i * 28, "×  " + t, 12.5, 400, INK)
    return s


def incident_triage():
    s = Svg(960, 600, "Something is wrong: where do I start?",
            "Decision guide for the most serious incidents, from a stolen key to a tampered log.",
            "Something is wrong: where do I start?", "Pick the closest description. The incident guide has the full steps.")
    s.card(370, 84, 220, 54, "What happened?", "", "gold")
    items = [
        ("A member's key or server is stolen", "Revoke the member now", "Authority: member-revoke\nThen re-register under a new member code", "red"),
        ("A node (vendor) is compromised", "Revoke the node", "Hosted members are cut off too.\nTheir own keys at their signers are intact", "red"),
        ("The CA key is exposed", "Treat the whole network as compromised", "Stop, rotate the CA, re-enrol everyone,\ngive out the new ca.pem", "red"),
        ("An operator token leaked", "Remove that operator", "operator-remove; the audit log shows\nwhat that token did", "gold"),
        ("A login issuer key leaked", "Remove it from citizen_assertion_keys", "Citizen answers stop until a new key\nis configured. Assertions last ≤ 10 min", "gold"),
        ("An audit log looks altered", "Verify the chain and the anchors", "zroad-cli audit-verify; compare with the\nother party's log of the same message", "blue"),
    ]
    cw, ch = 290, 168
    for i, (cause, action, detail, kind) in enumerate(items):
        col, row = i % 3, i // 3
        x = 30 + col * (cw + 15)
        y = 190 + row * (ch + 20)
        s.path(f"M 480,138 C 480,165 {x + cw / 2},165 {x + cw / 2},190", LINE, 1.5, arrow="end")
        bg, bd, t1 = {"red": (RED_BG, RED_BD, RED_TX), "gold": (GOLD_BG, GOLD_BD, GOLD_TX), "blue": (BLUE_BG, BLUE_BD, BLUE_TX)}[kind]
        s.rect(x, y, cw, ch, "#FFFFFF", bd, r=14, shadow=True)
        s.rect(x, y, cw, 52, bg, "none", r=14, sw=0)
        s.rect(x, y + 30, cw, 22, bg, "none", r=0, sw=0)
        # wrap cause
        words, line, ys = cause.split(), "", y + 22
        for wd in words:
            if len(line + " " + wd) > 31:
                s.text(x + 14, ys, line.strip(), 12.5, 700, t1)
                ys += 16
                line = wd
            else:
                line += " " + wd
        s.text(x + 14, ys, line.strip(), 12.5, 700, t1)
        s.text(x + 14, y + 76, action, 13, 700, INK)
        for j, d in enumerate(detail.split("\n")):
            s.text(x + 14, y + 100 + j * 18, d, 11.5, 400, MUTED)
        s.chip(x + 14, y + ch - 34, "see 06-incident-response", bg, t1, w=170, size=10.5)
    return s


def roadmap():
    s = Svg(960, 650, "Z-Road roadmap",
            "Phases 0 to 4 are done, phase 5 hardening is in progress, the pilot is gated on governance and review, then production readiness and scale.",
            "Roadmap", "Where Z-Road is and what comes next. Green is done, gold is under way, blue is planned.")
    phases = [
        ("0–4", "Foundations", "Done", "green", ["Protocol and threat model", "Security server, central server, timestamps", "Proof of concept → first use case", "Resilience, transparency, access control", "Catalogue, schemas, shared nodes, SDKs"]),
        ("5", "Hardening", "In progress", "gold", ["Fuzzing, fail-closed audit, renewal ✓", "Key custody: offline root CA + HSM", "Operator MFA / SSO", "Longer fuzz campaigns", "Independent security review"]),
        ("6", "Pilot", "Gated", "blue", ["One provider, a few consumers", "Real CA ceremony", "Data-sharing agreements", "Citizen login at the provider", "Measured against clear targets"]),
        ("7", "Production", "Planned", "blue", ["High availability", "Metrics and dashboards", "Signed releases, packages, SBOM", "Runbooks proven in drills", "More clients (PHP, C#, JS, Java)"]),
        ("8", "Scale", "Later", "blue", ["More services and members", "Federation with other exchanges", "Large payloads and streaming", "Ecosystem and ERP plug-ins", "Service-level reporting"]),
    ]
    x = 30
    w = 172
    for i, (n, name, status, kind, items) in enumerate(phases):
        bg, bd, tx, chipbg = {"green": (GREEN_BG, GREEN, GREEN_DK, GREEN), "gold": (GOLD_BG, GOLD_BD, GOLD_TX, GOLD_BD), "blue": (BLUE_BG, BLUE_BD, BLUE_TX, BLUE_BD)}[kind]
        s.rect(x, 96, w, 300, bg, bd, r=14, shadow=True)
        s.text(x + 14, 124, "PHASE " + n, 10.5, 700, tx, spacing="1.2")
        s.text(x + 14, 148, name, 16, 700, INK)
        s.chip(x + 14, 158, status, chipbg, "#fff" if kind == "green" else tx, w=84)
        import textwrap
        yy = 206
        for it in items:
            for k, ln in enumerate(textwrap.wrap(it, 23)):
                s.text(x + 14, yy, ("• " if k == 0 else "  ") + ln, 11, 400, INK)
                yy += 15
            yy += 7
        if i < len(phases) - 1:
            s.line(x + w, 220, x + w + 12, 220, LINE, 1.8, arrow="end")
        x += w + 12
    # parallel lane
    s.rect(30, 420, 900, 200, "#FFFFFF", GREEN_BD, r=16)
    s.text(50, 448, "RUNS IN PARALLEL, AND DECIDES WHETHER A PILOT HAPPENS", 10.5, 700, GREEN, spacing="1.2")
    lanes = [
        ("Governance", "Choose the authority; who may join; who runs the CA"),
        ("Legal", "Data protection review; data-sharing agreements; DPIA"),
        ("Assurance", "Independent code review and penetration test"),
        ("People", "Pilot partners (start with ZIMRA); training; communications"),
    ]
    for i, (n, d) in enumerate(lanes):
        y = 466 + i * 35
        s.rect(50, y, 120, 26, GOLD_BG, "none", r=13, sw=0)
        s.text(110, y + 17.5, n, 12, 700, GOLD_TX, "middle")
        s.text(184, y + 17.5, d, 12.5, 400, INK)
    return s


DIAGRAMS = {
    "roles-and-access": roles_and_access,
    "citizen-flow": citizen_flow,
    "hosted-member": hosted_member,
    "rotation-timeline": rotation_timeline,
    "sdk-layers": sdk_layers,
    "incident-triage": incident_triage,
    "roadmap": roadmap,
}
