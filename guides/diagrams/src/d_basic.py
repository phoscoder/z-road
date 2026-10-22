from svg import *


def network_overview():
    s = Svg(960, 600, "Z-Road at a glance",
            "The authority issues identities; organisations keep their own data and exchange signed, logged requests through security servers; citizens see who looked at their data.",
            "Z-Road at a glance", "Nobody stores a central copy of the data. Organisations ask each other, and every question is signed and logged.")
    # authority
    s.zone(250, 84, 460, 112, "The authority (one per network)", "gold")
    s.card(270, 112, 200, 70, "Central server", "CA + member directory", "gold")
    s.card(490, 112, 200, 70, "Timestamp authority", "dates the audit logs", "gold")
    # provider
    s.zone(24, 232, 330, 190, "Provider  (e.g. ZIMRA)")
    s.card(44, 270, 130, 90, "Internal system", "registry, database", "white")
    s.card(204, 270, 130, 90, "Security server", "signs · checks · logs", "green")
    s.line(174, 315, 204, 315, MUTED, 1.8, arrow="end")
    s.text(189, 392, "owns its data", 11.5, 400, MUTED, "middle", italic=True)
    # consumer
    s.zone(606, 232, 330, 190, "Consumer  (e.g. a company)")
    s.card(626, 270, 130, 90, "Security server", "signs · checks · logs", "green")
    s.card(786, 270, 130, 90, "Application", "ERP, portal, app", "white")
    s.line(786, 315, 756, 315, MUTED, 1.8, arrow="end")
    s.text(771, 392, "plain HTTP, private", 11.5, 400, MUTED, "middle", italic=True)
    # mtls
    s.line(334, 315, 626, 315, GREEN, 3.6, arrow="both")
    s.rect(402, 297, 156, 24, GREEN, "none", r=12, sw=0)
    s.text(480, 313.5, "mutual TLS channel", 12, 700, "#fff", "middle")
    s.text(480, 345, "signed · timestamped · logged", 11.5, 600, GREEN, "middle")
    # trust links
    s.path("M 330,182 C 330,230 270,225 270,270", LINE, 1.5, dash="5 5", arrow="end")
    s.path("M 630,182 C 630,230 690,225 690,270", LINE, 1.5, dash="5 5", arrow="end")
    s.text(480, 224, "identities and time, never the data", 11.5, 400, MUTED, "middle", italic=True)
    # citizen + portal
    s.zone(24, 450, 330, 128, "Citizens", "blue")
    s.card(44, 484, 130, 70, "Citizen", "logs in to the provider", "blue")
    s.card(204, 484, 130, 70, "Portal", "asks on their behalf", "blue")
    s.line(174, 519, 204, 519, BLUE_TX, 1.8, arrow="end")
    s.path("M 269,484 C 269,455 269,440 269,360", BLUE_TX, 1.8, dash="6 4", arrow="end")
    s.text(285, 452, "“who looked at my record?”", 11, 400, BLUE_TX, "start", italic=True)
    # shared node
    s.zone(606, 450, 330, 128, "Shared node (a vendor)", "grey")
    s.card(626, 484, 140, 70, "Hosted members", "keep their own keys", "white")
    s.card(786, 484, 130, 70, "Signer services", "on the members' machines", "soft")
    s.line(786, 519, 766, 519, MUTED, 1.6, arrow="end")
    s.path("M 771,484 C 771,455 771,440 771,360", LINE, 1.6, dash="6 4", arrow="end")
    s.text(790, 452, "same protocol", 11, 400, MUTED, "start", italic=True)
    # auditor
    s.card(380, 484, 170, 70, "Auditor", "verifies logs and proofs offline", "white")
    s.path("M 465,484 C 465,430 400,400 330,372", LINE, 1.4, dash="3 4", arrow="end")
    return s


def keys_and_trust():
    s = Svg(960, 690, "Who holds which key",
            "A table of every key and secret in a Z-Road network: who holds it, what it protects, and how serious it is if stolen.",
            "Who holds which key", "Know your secrets: the higher the impact, the better protected it should be.")
    cols = [(30, "Key or secret", 260), (290, "Held by", 190), (480, "What it does", 330), (810, "If stolen", 120)]
    y0 = 92
    s.rect(30, y0, 900, 34, GREEN, "none", r=10, sw=0)
    for x, t, w in cols:
        s.text(x + 14, y0 + 22, t, 12, 700, "#fff")
    rows = [
        ("Root CA key", "the authority", "Signs every member certificate.", "Critical", "red", "Offline or in an HSM"),
        ("Central TLS key", "central server", "Authenticates the directory to members.", "High", "gold", ""),
        ("Member key (one per organisation)", "the member", "Signs its messages and proves its identity.", "High", "gold", ""),
        ("Hosted member key", "the member's own signer", "Signs for a member that a vendor node carries.", "High", "gold", ""),
        ("Node key", "the vendor (node operator)", "Authenticates the shared node's TLS.", "High", "gold", ""),
        ("Timestamp authority key", "the authority", "Dates audit-log heads.", "High", "gold", ""),
        ("Citizen login issuer key", "the provider's login system", "Vouches that a citizen controls an identifier.", "High", "gold", ""),
        ("Operator and portal tokens", "named people and portals", "Administration; portals ask only citizen questions.", "Medium", "blue", "Stored only as hashes"),
        ("Subject key", "each security server", "Keyed hash that keeps identifiers out of the logs.", "Medium", "blue", ""),
        ("Enrolment token", "a new member, once", "Lets one organisation obtain its first certificate.", "Low", "soft", "Single use"),
    ]
    y = y0 + 40
    for i, (name, who, what, level, kind, note) in enumerate(rows):
        h = 44
        s.rect(30, y, 900, h, "#FFFFFF" if i % 2 == 0 else "#F6F9F7", "#E3EAE5", r=8, sw=1)
        s.text(44, y + 19, name, 13, 600, INK)
        if note:
            s.text(44, y + 35, note, 11, 400, MUTED, italic=True)
        s.text(304, y + 26, who, 12.5, 400, INK)
        s.text(494, y + 26, what, 12, 400, INK)
        bg, tx = {"red": (RED_BG, RED_TX), "gold": (GOLD_BG, GOLD_TX), "blue": (BLUE_BG, BLUE_TX), "soft": (GREEN_BG, GREEN)}[kind]
        s.chip(824, y + 11, level, bg, tx, w=78)
        y += h + 5
    return s


def secure_topology():
    s = Svg(960, 640, "A secure network layout for one security server",
            "Network zones: peers reach only the mutual TLS port; internal systems and administrators stay on private networks; secrets live in a vault or HSM.",
            "A secure layout for one node", "Only one port faces other organisations. Everything else stays private.")
    # zones
    s.zone(20, 92, 200, 400, "Other members", "grey")
    s.zone(240, 92, 210, 400, "DMZ", "gold")
    s.zone(470, 92, 270, 400, "Internal network", "soft")
    s.zone(760, 92, 180, 400, "Management", "blue")
    s.card(40, 140, 160, 70, "Peer security servers", "mutual TLS only", "white")
    s.card(40, 232, 160, 70, "Central server", "directory, CA", "white")
    s.card(40, 324, 160, 70, "Timestamp authority", "", "white")
    # firewall bar and the paths through it
    s.rect(224, 120, 12, 350, "#B42318", "none", r=3, sw=0)
    s.text(20, 512, "Firewall: only member addresses may reach port 7443. Nothing else is exposed.", 11.5, 600, "#B42318")
    s.card(252, 150, 190, 100, "Security server", "network listener :7443", "green", "client certificates required")
    s.line(200, 175, 252, 195, GREEN, 2.6, arrow="end")
    s.line(200, 267, 256, 238, LINE, 1.6, arrow="end", dash="4 4")
    s.line(200, 359, 266, 248, LINE, 1.6, arrow="end", dash="4 4")
    s.text(262, 300, "A reverse proxy or rate", 11, 400, MUTED, "start", italic=True)
    s.text(262, 314, "limiting can sit in front.", 11, 400, MUTED, "start", italic=True)
    # internal listener
    s.card(485, 150, 215, 100, "Internal listener", "same process, private address", "soft", "e.g. 10.0.0.5:7001")
    s.line(442, 200, 485, 200, MUTED, 1.8)
    s.card(485, 290, 130, 70, "Internal system", "upstream :9001", "white")
    s.card(630, 290, 90, 70, "Database", "", "white")
    s.line(550, 250, 550, 290, MUTED, 1.8, arrow="end")
    s.line(615, 325, 630, 325, MUTED, 1.8, arrow="end")
    s.card(485, 390, 235, 70, "Your applications", "call the internal listener", "white")
    s.line(602, 390, 602, 250, MUTED, 1.4, arrow="end", dash="4 4")
    # management
    s.card(780, 140, 140, 70, "Operators", "named tokens, roles", "blue")
    s.card(780, 232, 140, 70, "Bastion / VPN", "the only way in", "blue")
    s.card(780, 324, 140, 70, "Monitoring", "logs, alerts", "blue")
    s.card(780, 410, 140, 60, "Backups", "encrypted, offline copy", "blue")
    s.path("M 780,267 C 750,267 740,215 700,205", BLUE_TX, 1.6, arrow="end")
    # vault
    s.rect(240, 530, 700, 84, GOLD_BG, GOLD_BD, r=14, sw=1.2)
    s.text(258, 554, "SECRETS", 10.5, 700, "#9A7B00", spacing="1.2")
    s.text(258, 580, "Private keys (key.pem), CA key, operator tokens:", 12.5, 600, GOLD_TX)
    s.text(258, 598, "0600 files owned by the service user at minimum; an HSM or vault for the CA key. Never in images, chat or tickets.", 11.5, 400, "#8A6D00")
    s.line(420, 250, 420, 530, GOLD_BD, 1.4, dash="3 4")
    return s


def request_journey():
    s = Svg(960, 480, "The journey of one request",
            "Six steps from an application's question to a signed, provable answer.",
            "The journey of one request", "What happens when a company checks a supplier's tax clearance.")
    steps = [
        ("Ask", "The application calls its own security server over private HTTP."),
        ("Sign", "Schema check, then the request is signed and logged."),
        ("Send", "Mutual TLS to the provider's security server."),
        ("Verify", "Member active? Signature valid? Allowed? Schema ok? Not a replay? Logged first."),
        ("Answer", "The provider's system answers; the answer is signed."),
        ("Prove", "The consumer verifies it and keeps the proof."),
    ]
    x = 30
    w = 140
    for i, (t, d) in enumerate(steps):
        kind = "green" if i in (1, 3, 5) else "white"
        s.rect(x, 110, w, 190, "#FFFFFF" if kind == "white" else GREEN_BG, GREEN_BD if kind == "white" else GREEN, r=14, shadow=True)
        s.badge(x + 24, 138, i + 1)
        s.text(x + 46, 143, t, 14, 700, INK)
        # wrap description
        words = d.split()
        line, ys = "", 176
        for wd in words:
            if len(line + " " + wd) > 19:
                s.text(x + 14, ys, line.strip(), 12, 400, MUTED)
                ys += 17
                line = wd
            else:
                line += " " + wd
        s.text(x + 14, ys, line.strip(), 12, 400, MUTED)
        if i < len(steps) - 1:
            s.line(x + w, 205, x + w + 12, 205, GREEN, 2.2, arrow="end")
        x += w + 12
    # who
    s.rect(30, 322, 444, 30, GREEN_BG, "none", r=10, sw=0)
    s.text(252, 342, "consumer side", 12, 700, GREEN, "middle")
    s.rect(486, 322, 292, 30, GOLD_BG, "none", r=10, sw=0)
    s.text(632, 342, "provider side", 12, 700, GOLD_TX, "middle")
    s.rect(790, 322, 140, 30, GREEN_BG, "none", r=10, sw=0)
    s.text(860, 342, "consumer side", 12, 700, GREEN, "middle")
    s.rect(30, 380, 900, 76, "#FFFFFF", GREEN_BD, r=12)
    s.text(48, 404, "Left behind, on both sides:", 12.5, 700, INK)
    s.text(48, 426, "a hash-chained audit entry (with the date proven by the timestamp authority), and the signed proof of the exchange.", 12, 400, MUTED)
    s.text(48, 444, "Nothing is stored centrally. Neither side can quietly rewrite what happened.", 12, 400, MUTED)
    return s
