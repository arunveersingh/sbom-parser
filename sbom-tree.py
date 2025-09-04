#!/usr/bin/env python3
# sbom-tree.py — draw dependency trees from a CycloneDX (or simple SPDX) JSON SBOM.
#
# Outputs:
#   --format ascii   : ASCII tree to stdout (default)
#   --format html    : Single-file interactive HTML (collapsible + search + pinned highlight)
#   --format dot     : Graphviz DOT (use: dot -Tpng out.dot -o out.png)
#
# Examples:
#   python3 sbom-tree.py sbom.json --format ascii --max-depth 2
#   python3 sbom-tree.py sbom.json --format html --output deps.html
#   python3 sbom-tree.py sbom.json --format dot  --output deps.dot

import argparse, json, sys
from collections import defaultdict, deque
from typing import Dict, List, Set, Optional

# ----------------- Parse SBOM -----------------

class SBOM:
    def __init__(self):
        self.nodes: Dict[str, str] = {}         # node_id -> label
        self.edges: Dict[str, Set[str]] = defaultdict(set)  # node_id -> children
        self.roots: Set[str] = set()

    @staticmethod
    def from_json(obj: dict) -> "SBOM":
        if isinstance(obj, dict) and (obj.get("bomFormat") == "CycloneDX" or "components" in obj or "dependencies" in obj):
            return SBOM._from_cyclonedx(obj)
        if isinstance(obj, dict) and ("packages" in obj or "relationships" in obj):
            return SBOM._from_spdx(obj)
        raise ValueError("Unsupported SBOM format. Expected CycloneDX JSON (preferred) or SPDX JSON.")

    @staticmethod
    def _cx_label(comp: dict) -> str:
        name = comp.get("name") or comp.get("group") or comp.get("type") or "component"
        version = comp.get("version")
        group = comp.get("group")
        label = (f"{group}/{name}" if group and group != name else name)
        return f"{label}@{version}" if version else label

    @staticmethod
    def _from_cyclonedx(obj: dict) -> "SBOM":
        s = SBOM()
        comps = obj.get("components", []) or []
        for c in comps:
            cid = c.get("bom-ref") or c.get("bomRef") or c.get("purl") or c.get("name")
            if cid:
                s.nodes[cid] = SBOM._cx_label(c)

        meta = obj.get("metadata", {}) or {}
        meta_comp = meta.get("component")
        root_id = None
        if meta_comp:
            root_id = meta_comp.get("bom-ref") or meta_comp.get("bomRef") or meta_comp.get("purl") or meta_comp.get("name")
            if root_id:
                s.nodes.setdefault(root_id, SBOM._cx_label(meta_comp))
                s.roots.add(root_id)

        for dep in obj.get("dependencies", []) or []:
            ref = dep.get("ref")
            if not ref:
                continue
            s.nodes.setdefault(ref, ref)
            for child in (dep.get("dependsOn") or []):
                if not child: continue
                s.nodes.setdefault(child, child)
                s.edges[ref].add(child)

        if not s.edges and comps:
            for c in comps:
                src = c.get("bom-ref") or c.get("bomRef") or c.get("purl") or c.get("name")
                deps_field = c.get("dependencies") or []
                if isinstance(deps_field, list):
                    for child in deps_field:
                        s.nodes.setdefault(src, src)
                        s.nodes.setdefault(child, child)
                        s.edges[src].add(child)

        all_children = {k for kids in s.edges.values() for k in kids}
        candidates = set(s.nodes.keys()) - all_children
        if candidates:
            s.roots.update(candidates)
        if root_id:
            s.roots = {root_id}

        if root_id and root_id in s.nodes and root_id not in s.edges:
            in_deps = {c for kids in s.edges.values() for c in kids}
            top_level = sorted([r for r in s.edges.keys() if r not in in_deps])
            if top_level:
                s.edges[root_id] = set(top_level)

        return s

    @staticmethod
    def _spdx_pkg_label(pkg: dict) -> str:
        name = pkg.get("name") or "package"
        version = pkg.get("versionInfo") or pkg.get("version")
        return name if not version else f"{name}@{version}"

    @staticmethod
    def _from_spdx(obj: dict) -> "SBOM":
        s = SBOM()
        for pkg in obj.get("packages", []) or []:
            sid = pkg.get("SPDXID") or pkg.get("spdxid")
            if sid:
                s.nodes[sid] = SBOM._spdx_pkg_label(pkg)

        reverse_types = {
            "RUNTIME_DEPENDENCY_OF","BUILD_DEPENDENCY_OF","DEV_DEPENDENCY_OF",
            "TEST_DEPENDENCY_OF","OPTIONAL_DEPENDENCY_OF",
            "STATIC_LINK","DYNAMIC_LINK",
            "DATA_FILE_OF","EXAMPLE_OF","GENERATED_FROM","PATCH_FOR",
            "PREREQUISITE_FOR","AMENDS","DEPENDENCY_MANIFEST_OF",
        }
        forward_types = {"DEPENDS_ON","PREREQUISITE"}

        for rel in obj.get("relationships", []) or []:
            rt = (rel.get("relationshipType") or "").upper().replace("-", "_")
            src = rel.get("spdxElementId") or rel.get("sourceElement")
            dst = rel.get("relatedSpdxElement") or rel.get("targetElement")
            if not src or not dst:
                continue
            s.nodes.setdefault(src, src); s.nodes.setdefault(dst, dst)
            if rt in forward_types:
                s.edges[src].add(dst)
            elif rt in reverse_types:
                s.edges[dst].add(src)

        desc = obj.get("documentDescribes") or []
        if isinstance(desc, str): desc = [desc]
        for rid in desc:
            if rid in s.nodes:
                s.roots.add(rid)
        if not s.roots:
            in_edges = {c for kids in s.edges.values() for c in kids}
            s.roots = set(s.nodes.keys()) - in_edges
        return s

# ----------------- Build forest -----------------

def build_forest(sbom: SBOM, start_ids: Optional[List[str]] = None) -> List[str]:
    if start_ids:
        roots = [rid for rid in start_ids if rid in sbom.nodes]
        if roots:
            return roots
    return sorted(sbom.roots, key=lambda rid: sbom.nodes.get(rid, rid).lower())

# ----------------- ASCII -----------------

def ascii_trees(sbom: SBOM, roots: List[str], show_ids: bool=False, max_depth: Optional[int]=None, include_dupes: bool=False):
    visited_global: Set[str] = set()
    def render(node: str, prefix: str="", seen: Optional[Set[str]]=None, last: bool=True, depth: int=0):
        if seen is None: seen = set()
        label = sbom.nodes.get(node, node)
        node_text = f"{label} <{node}>" if show_ids else label
        tee = "+-- " if depth>0 else ""
        yield prefix + tee + node_text
        if max_depth is not None and depth >= max_depth: return
        if node in seen:
            yield prefix + ("    " if last else "|   ") + "+-- (cycle)"
            return
        seen = seen | {node}
        children = sorted(sbom.edges.get(node, []), key=lambda rid: sbom.nodes.get(rid, rid).lower())
        for i, child in enumerate(children):
            last_child = (i == len(children)-1)
            next_prefix = prefix + ("    " if last else "|   ")
            if not include_dupes and child in visited_global:
                yield next_prefix + "+-- " + sbom.nodes.get(child, child) + "  (seen)"
                continue
            visited_global.add(child)
            for line in render(child, next_prefix, seen, last_child, depth+1):
                yield line
    for r in roots:
        for line in render(r, "", set(), True, 0):
            print(line)
        print()

# ----------------- DOT -----------------

def to_dot(sbom: SBOM, roots: List[str]) -> str:
    reachable = set()
    for root in roots:
        dq = deque([root])
        while dq:
            n = dq.popleft()
            if n in reachable: continue
            reachable.add(n)
            for c in sbom.edges.get(n, []): dq.append(c)
    lines = ['digraph SBOM {', '  rankdir=LR;', '  node [shape=box, fontsize=10];']
    for n in sorted(reachable):
        label = sbom.nodes.get(n, n).replace('"','\\"')
        lines.append(f'  "{n}" [label="{label}"];')
    for src in sorted(reachable):
        for dst in sorted(sbom.edges.get(src, [])):
            if dst in reachable: lines.append(f'  "{src}" -> "{dst}";')
    lines.append('}')
    return "\n".join(lines)

# ----------------- HTML -----------------

HTML_TEMPLATE = r"""<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>SBOM Dependency Tree</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  :root{
    --indent: 28px;
    --btn: 20px;
    --font: 13px ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace;
    --line-strong:#9ca3af;
    --path:#16a34a;        /* green for boxes (selected chain) */
    --parent-line:#dc2626; /* red for the path to parents */
  }
  body{ margin:0; font-family: system-ui,-apple-system,Segoe UI,Roboto,"Helvetica Neue",Arial,"Noto Sans",sans-serif; }
  header{ padding:12px 16px; background:#111827; color:#e5e7eb; }
  main{ padding:12px 16px; }
  .controls{ display:flex; gap:10px; flex-wrap:wrap; margin-bottom:10px; }
  input[type="search"],button{ padding:6px 10px; border:1px solid #d1d5db; border-radius:8px; }
  button{ background:#f9fafb; cursor:pointer; }
  button:hover{ background:#eef2ff; }
  #viewport{ height:78vh; border:1px solid #e5e7eb; border-radius:10px; background:#fff; overflow:auto; }

  ul.tree{ list-style:none; margin:0; padding:10px 12px; font: var(--font); }
  ul.tree ul{ list-style:none; margin:0; padding-left: var(--indent); position:relative; }
  /* base vertical spine */
  ul.tree ul::before{
    content:""; position:absolute; left: calc(var(--btn)/2); top:0; bottom:0;
    border-left:2px solid var(--line-strong); z-index:0;
  }
  /* red vertical spine along the selected chain (can be many levels) */
  ul.tree ul.parent-v::before{
    border-left-color: var(--parent-line);
    z-index: 2;
  }

  li.node{ position:relative; margin:4px 0; }
  /* elbow from parent column to this node */
  li.node::before{
    content:""; position:absolute; left: calc(var(--btn)/2); top: calc(var(--btn)/2 - 1px);
    width: calc(var(--indent) - var(--btn)/2); border-top:2px solid var(--line-strong); z-index:0;
  }
  /* red elbows along the selected chain (can be many levels) */
  li.node.parent-link::before{ border-top-color: var(--parent-line); z-index: 2; }

  .row{
    display:flex; align-items:flex-start; gap:10px; line-height:1.4;
    box-sizing:border-box; padding:2px 6px; border:2px dashed transparent; border-radius:4px;
  }
  .btn{ position:relative; z-index:2; flex:none; width:var(--btn); height:var(--btn); border-radius:50%; display:flex; align-items:center; justify-content:center; font-weight:600; font-size:12px; background:#111827; color:#fff; border:1px solid #111827; cursor:pointer; }
  .btn.leaf{ background:#e5e7eb; color:#374151; border-color:#9ca3af; cursor:default; }
  .label{ max-width:1600px; overflow-wrap:anywhere; }
  .badge{ color:#6b7280; font-size:11px; margin-left:4px; }
  .collapsed > ul{ display:none; }

  .match .label{ background:#fff7ed; outline:1px solid #fed7aa; border-radius:4px; padding:0 3px; }

  /* selected chain boxes */
  li.node.active  > .row{ border-color: var(--path); }
  li.node.ancestor > .row{ border-color: var(--path); }

  /* soft hover only when not part of path */
  li.node:not(.active):not(.ancestor):hover > .row{
    background:linear-gradient(90deg, rgba(191,219,254,.25), transparent 55%);
    border-radius:4px;
  }
</style>
</head>
<body>
<header><h1>SBOM Dependency Tree</h1></header>
<main>
  <div class="controls">
    <input id="q" type="search" placeholder="Search (Enter)">
    <button id="expand">Expand all</button>
    <button id="collapse">Collapse all</button>
    <button id="clearSel">Clear selection</button>
    <span id="status">No matches</span>
  </div>
  <div id="viewport"><ul id="tree" class="tree"></ul></div>
</main>

<script>
const data = __DATA__;
const $  = (sel, root=document) => root.querySelector(sel);
const $$ = (sel, root=document) => Array.from(root.querySelectorAll(sel));
function el(t,a={},...c){const e=document.createElement(t);for(const[k,v]of Object.entries(a)){if(k==="class")e.className=v;else if(k.startsWith("on"))e.addEventListener(k.slice(2),v);else e.setAttribute(k,v);}for(const x of c){if(x!=null)e.appendChild(typeof x==="string"?document.createTextNode(x):x);}return e;}
const hasKids = n => Array.isArray(n.children) && n.children.length>0;

let pinned = null;
let pinnedLis = [];
let pinnedUls = [];

/* Collect all LIs (node, ancestors) and all ULs (each parent's children list) up to root */
function computeChain(li){
  const lis = [li];
  const uls = [];
  let p = li.parentElement; // start at UL that contains the selected LI
  while (p && p.id !== "tree"){
    if (p.tagName === "UL"){
      uls.push(p);                  // this UL draws the vertical spine segment
      const pli = p.parentElement;  // parent LI that owns this UL
      if (pli && pli.classList.contains("node")) lis.push(pli);
    }
    p = p.parentElement;
  }
  return { lis, uls }; // immediate parent UL first; root-most last
}

function clearPinned(){
  for (const n of pinnedLis){ n.classList.remove("active","ancestor","parent-link"); }
  for (const u of pinnedUls){ u.classList.remove("parent-v"); }
  pinnedLis = []; pinnedUls = []; pinned = null;
}

function setPinned(li){
  if (pinned === li){ clearPinned(); return; }
  // compute chain once; O(depth)
  const { lis, uls } = computeChain(li);

  // clear previous marks; O(old depth)
  for (const n of pinnedLis){ n.classList.remove("active","ancestor","parent-link"); }
  for (const u of pinnedUls){ u.classList.remove("parent-v"); }

  // green dotted boxes on the whole chain
  lis[0].classList.add("active");
  for (let i=1;i<lis.length;i++) lis[i].classList.add("ancestor");

  // red path all the way to root: elbows + vertical spines for every level in chain
  for (const n of lis) n.classList.add("parent-link");
  for (const u of uls) u.classList.add("parent-v");

  pinned = li; pinnedLis = lis; pinnedUls = uls;
}

function buildList(root){
  const container = $("#tree"); container.innerHTML = "";
  function build(n, depth){
    const li   = el("li",{class:`node ${depth===0?"expanded":"collapsed"} depth-${depth}`});
    const leaf = !hasKids(n);
    const btn   = el("div",{class:`btn ${leaf?"leaf":""}`}, leaf?"•":(depth===0?"−":"+"));
    const label = el("div",{class:"label"}, n.name || "");
    const badge = hasKids(n)?el("span",{class:"badge"},`(${n.children.length})`):null;
    const row   = el("div",{class:"row"}, btn, label, badge);
    li.appendChild(row);
    if (hasKids(n)){
      const ul = el("ul",{}); n.children.forEach(c=>ul.appendChild(build(c,depth+1))); li.appendChild(ul);
      btn.addEventListener("click",evt=>{
        evt.stopPropagation();
        const open=li.classList.contains("expanded");
        li.classList.toggle("expanded",!open);
        li.classList.toggle("collapsed",open);
        btn.textContent=open?"+":"−";
      });
    }
    row.addEventListener("click",evt=>{ if(evt.target!==btn) setPinned(li); });
    return li;
  }
  container.appendChild(build(root,0));
}

function applySearch(term){
  const status=$("#status"); $$(".match",$("#tree")).forEach(li=>li.classList.remove("match"));
  if(!term){status.textContent="No matches"; return;}
  term=term.toLowerCase(); let hits=0;
  $$("#tree li.node .label").forEach(lbl=>{
    if((lbl.textContent||"").toLowerCase().includes(term)){
      hits++; const li=lbl.closest("li.node"); li.classList.add("match");
      // expand up to root; O(depth)
      let p=li.parentElement;
      while(p&&p.id!=="tree"){
        if(p.tagName==="UL"){
          const pli=p.parentElement;
          if(pli&&pli.classList.contains("collapsed")){
            pli.classList.remove("collapsed"); pli.classList.add("expanded");
            const b=pli.querySelector(":scope > .row .btn"); if(b&&!b.classList.contains("leaf")) b.textContent="−";
          }
        }
        p=p.parentElement;
      }
    }
  });
  status.textContent = hits ? `Found ${hits} match(es)` : "No matches";
}

/* controls */
$("#expand").onclick = () => {
  $$("#tree li.node.collapsed").forEach(li=>{
    li.classList.remove("collapsed"); li.classList.add("expanded");
    const b=li.querySelector(":scope > .row .btn"); if(b && !b.classList.contains("leaf")) b.textContent="−";
  });
};
$("#collapse").onclick = () => {
  $$("#tree li.node.expanded").forEach(li=>{
    if (li.parentElement && li.parentElement.id === "tree") return;
    li.classList.remove("expanded"); li.classList.add("collapsed");
    const b=li.querySelector(":scope > .row .btn"); if(b && !b.classList.contains("leaf")) b.textContent="+";
  });
};
$("#clearSel").onclick = () => clearPinned();
$("#q").addEventListener("keydown", e => { if (e.key === "Enter") applySearch(e.target.value.trim()); });
document.addEventListener("keydown", e => { if (e.key === "Escape") clearPinned(); });

buildList(data);
</script>
</body>
</html>
"""

def to_d3_tree(sbom: SBOM, roots: List[str]) -> dict:
    def make_node(node: str, seen: Set[str]) -> dict:
        label = sbom.nodes.get(node, node)
        if node in seen:
            return {"name": label + " ↺", "children": []}
        seen = seen | {node}
        kids = sorted(sbom.edges.get(node, []), key=lambda rid: sbom.nodes.get(rid, rid).lower())
        return {"name": label, "children": [ make_node(k, seen) for k in kids ]}
    if len(roots) == 1:
        return make_node(roots[0], set())
    return {"name": "SBOM Roots", "children": [ make_node(r, set()) for r in roots ]}

# ----------------- CLI -----------------

def main():
    ap = argparse.ArgumentParser(description="Draw dependency trees from a CycloneDX/SPDX SBOM JSON")
    ap.add_argument("sbom", help="Path to SBOM JSON")
    ap.add_argument("--format", "-f", choices=["ascii","html","dot"], default="ascii")
    ap.add_argument("--output", "-o", help="Output file for html/dot (required for html)")
    ap.add_argument("--root", action="append", help="Start from specific node id(s) (bom-ref/SPDXID). Repeatable.")
    ap.add_argument("--show-ids", action="store_true", help="ASCII: show internal IDs next to labels")
    ap.add_argument("--max-depth", type=int, default=None, help="ASCII: depth limit (root=0)")
    ap.add_argument("--include-dupes", action="store_true", help="ASCII: don’t collapse repeated nodes")
    args = ap.parse_args()

    # Load JSON
    try:
        with open(args.sbom, "r", encoding="utf-8") as f:
            obj = json.load(f)
    except Exception as e:
        print(f"Failed to read SBOM JSON: {e}", file=sys.stderr)
        sys.exit(2)

    # Parse
    try:
        s = SBOM.from_json(obj)
    except Exception as e:
        print(f"Failed to parse SBOM: {e}", file=sys.stderr)
        sys.exit(3)

    roots = build_forest(s, args.root)
    if not roots:
        print("No roots found to render.", file=sys.stderr)
        sys.exit(4)

    if args.format == "ascii":
        ascii_trees(
            s,
            roots,
            show_ids=args.show_ids,
            max_depth=args.max_depth,
            include_dupes=args.include_dupes,
        )
        if all(not s.edges.get(r) for r in roots):
            print("\n(Heads up: no dependency edges were found under the root. "
                  "For CycloneDX, ensure top-level 'dependencies' or per-component 'dependencies' are present.)")
        return

    if args.format == "dot":
        dot = to_dot(s, roots)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f: f.write(dot)
            print(f"Wrote DOT to {args.output}")
        else:
            print(dot)
        return

    if args.format == "html":
        if not args.output:
            print("Please provide --output path ending with .html", file=sys.stderr)
            sys.exit(5)
        data = to_d3_tree(s, roots)
        html = HTML_TEMPLATE.replace("__DATA__", json.dumps(data, ensure_ascii=False))
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(html)
        print(f"Wrote interactive HTML to {args.output}")
        return

if __name__ == "__main__":
    main()
