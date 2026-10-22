import os, sys
sys.path.insert(0, os.path.dirname(__file__))
import d_basic

OUT = os.path.join(os.path.dirname(__file__), "..")
DOCS = os.path.join(os.path.dirname(__file__), "..", "..", "..", "docs", "diagrams")

ALL = {
    "network-overview": d_basic.network_overview,
    "keys-and-trust": d_basic.keys_and_trust,
    "secure-topology": d_basic.secure_topology,
    "request-journey": d_basic.request_journey,
}
for mod in ("d_flows", "d_more"):
    try:
        m = __import__(mod)
        ALL.update(m.DIAGRAMS)
    except ImportError:
        pass

only = sys.argv[1:] or list(ALL)
for name in only:
    svg = ALL[name]().render()
    target = DOCS if name == "roadmap" else OUT
    with open(os.path.join(target, name + ".svg"), "w") as f:
        f.write(svg)
    print("wrote", name)
