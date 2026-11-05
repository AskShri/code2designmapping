"""Function-level call graph across files (JavaScript/TypeScript, Python, Go, Java, C#).

Functions are keyed by (file, name); module-level code is (file, "<module>"); anonymous functions
are (file, "<anon:LINE>"). Edges are resolved through the file index's import bindings; Go, Java
and C# resolve within the same directory (package) by name. The graph is used to attribute store
and outbound calls to the request handler that reaches them.
"""
import os, re
from collections import deque
from .index import walk

FUNC_TYPES = {
    "javascript": {"function_declaration", "function_expression", "arrow_function", "method_definition", "generator_function_declaration", "function"},
    "typescript": {"function_declaration", "function_expression", "arrow_function", "method_definition", "generator_function_declaration", "function"},
    "tsx": {"function_declaration", "function_expression", "arrow_function", "method_definition", "generator_function_declaration", "function"},
    "python": {"function_definition", "lambda"},
    "go": {"function_declaration", "method_declaration", "func_literal"},
    "java": {"method_declaration", "constructor_declaration", "lambda_expression"},
    "c_sharp": {"method_declaration", "constructor_declaration", "local_function_statement", "lambda_expression"},
}
CALL_TYPES = {"call_expression", "call", "method_invocation", "invocation_expression", "object_creation_expression", "new_expression"}


class CallGraph:
    def __init__(self, idx):
        self.idx = idx
        self.functions = {}   # (file, name) -> (start_line, end_line)
        self.calls = {}       # (file, name) -> set((file, name))
        self._spans = {}      # file -> sorted list of (start, end, name)
        self._by_dir_name = {}  # (dir, name) -> file   (Go/Java/C# package-level lookup)
        self.reexports = {}     # file -> {exported name: target file}
        for f, sf in idx.files.items():
            self._collect(sf)
            self._collect_reexports(sf)
        for f, sf in idx.files.items():
            self._edges(sf)

    # ------------------------------------------------------------ collection
    def _name_of(self, sf, n):
        t = n.type
        if t in ("function_declaration", "generator_function_declaration", "method_definition", "function_definition", "method_declaration", "constructor_declaration", "local_function_statement"):
            nm = n.child_by_field_name("name")
            if nm is not None:
                return sf.node_text(nm)
        p = n.parent
        hops = 0
        while p is not None and p.type in ("arguments", "call_expression", "parenthesized_expression", "await_expression") and hops < 4:
            p = p.parent; hops += 1
        if p is None:
            return None
        if p.type == "variable_declarator":
            nm = p.child_by_field_name("name")
            return sf.node_text(nm) if nm is not None and nm.type == "identifier" else None
        if p.type == "assignment_expression":
            left = sf.node_text(p.child_by_field_name("left"))
            if left.startswith(("exports.", "module.exports.")):
                return left.split(".")[-1]
            if left == "module.exports":
                return "<default>"
            m = re.match(r"\w+\.prototype\.(\w+)$", left)
            if m:
                return m.group(1)
            return left.split(".")[-1] if re.match(r"^[\w.]+$", left) else None
        if p.type == "pair":
            return sf.node_text(p.child_by_field_name("key")).strip("'\"")
        if p.type == "export_statement" or (p.type == "parenthesized_expression" and p.parent is not None and p.parent.type == "export_statement"):
            return "<default>"
        if p.type == "assignment" and sf.lang == "python":
            return sf.node_text(p.child_by_field_name("left"))
        return None

    def _collect(self, sf):
        root = sf.tree.root_node
        spans = [(1, len(sf.lines) or 1, "<module>")]
        self.functions[(sf.path, "<module>")] = (1, len(sf.lines) or 1)
        for n in walk(root):
            if n.type not in FUNC_TYPES.get(sf.lang, set()):
                continue
            name = self._name_of(sf, n)
            if sf.lang == "go" and n.type == "method_declaration":
                nm = n.child_by_field_name("name"); name = sf.node_text(nm) if nm is not None else None
            if name is None:
                name = f"<anon:{sf.line(n)}>"
            key = (sf.path, name)
            span = (sf.line(n), sf.end_line(n))
            same = [k for k, v in self.functions.items() if k[0] == sf.path and v == span]
            if same:
                if name.startswith("<anon") or any(not k[1].startswith("<anon") for k in same):
                    continue  # a function with this exact span is already known under a better name
                for k in same:  # replace the anonymous entry with the named one
                    del self.functions[k]
                    spans[:] = [sp for sp in spans if not (sp[0] == span[0] and sp[1] == span[1] and sp[2] == k[1])]
            if key in self.functions and self.functions[key] != span:
                name = f"{name}#{sf.line(n)}"; key = (sf.path, name)
            self.functions[key] = span
            spans.append((span[0], span[1], name))
            self._by_dir_name.setdefault((os.path.dirname(sf.path), name.split("#")[0]), sf.path)
        spans.sort(key=lambda s: (s[1] - s[0], s[0]))
        self._spans[sf.path] = spans

    def _collect_reexports(self, sf):
        if sf.lang not in ("javascript", "typescript", "tsx"):
            return
        rx = {}
        for m in re.finditer(r"(?:module\.exports|exports)\.(\w+)\s*=\s*require\(\s*['\"]([^'\"]+)['\"]\s*\)", sf.text):
            t = self.idx.resolve(sf, m.group(2))
            if t: rx[m.group(1)] = t
        for m in re.finditer(r"export\s*\{([^}]*)\}\s*from\s*['\"]([^'\"]+)['\"]", sf.text):
            t = self.idx.resolve(sf, m.group(2))
            if t:
                for nm in m.group(1).split(","):
                    nm = nm.strip().split(" as ")[-1].strip()
                    if nm: rx[nm] = t
        for m in re.finditer(r"export\s*\*\s*from\s*['\"]([^'\"]+)['\"]", sf.text):
            t = self.idx.resolve(sf, m.group(1))
            if t: rx.setdefault("*", []).append(t) if isinstance(rx.get("*"), list) else rx.__setitem__("*", [t])
        # const x = require('./x'); module.exports = { x, y }
        obj = re.search(r"module\.exports\s*=\s*\{([^}]*)\}", sf.text)
        if obj:
            for nm in obj.group(1).split(","):
                nm = nm.strip().split(":")[0].strip()
                if nm in sf.bindings:
                    t = self.idx.resolve(sf, sf.bindings[nm])
                    if t: rx.setdefault(nm, t)
        if rx:
            self.reexports[sf.path] = rx

    def follow(self, file, members):
        """Follow re-exports: (controllers/index.js, ['authController', 'register']) -> (auth.controller.js, ['register'])."""
        for _ in range(4):
            rx = self.reexports.get(file)
            if not rx or not members:
                return file, members
            if members[0] in rx and not isinstance(rx[members[0]], list):
                file, members = rx[members[0]], members[1:]
                continue
            if isinstance(rx.get("*"), list):
                for t in rx["*"]:
                    if self.function_at(t, members[0]) or members[0] in self.reexports.get(t, {}):
                        file = t; break
                else:
                    return file, members
                continue
            return file, members
        return file, members

    def resolve_ref(self, sf, text):
        """Resolve a callee/handler reference text ('ctrl.register', 'svc.homeHandler') to a function key."""
        parts = [p for p in re.split(r"[.?!]+", re.sub(r"\s+", "", text).split("(")[0]) if p]
        if not parts:
            return None
        return self._resolve(sf, parts[0], parts[1:])

    def package_functions(self, file):
        d = os.path.dirname(file)
        return sorted(k for k in self.functions if os.path.dirname(k[0]) == d and not k[1].startswith("<"))

    def enclosing(self, file, line):
        for s, e, name in self._spans.get(file, []):
            if s <= line <= e:
                return (file, name)
        return (file, "<module>")

    def function_at(self, file, name):
        if (file, name) in self.functions:
            return (file, name)
        for key in self.functions:
            if key[0] == file and key[1].split("#")[0] == name:
                return key
        return None

    # ------------------------------------------------------------ edges
    def _resolve(self, sf, root, members):
        """Resolve a callee to a function key, or None."""
        f = sf.path
        if root in ("this", "self", "cls") and members:
            k = self.function_at(f, members[0])
            if k: return k
            if sf.lang in ("go", "java", "c_sharp"):
                tf = self._by_dir_name.get((os.path.dirname(f), members[0]))
                if tf: return self.function_at(tf, members[0])
            return None
        if not members:
            k = self.function_at(f, root)
            if k: return k
        if sf.lang in ("go", "java", "c_sharp"):
            name = members[-1] if members else root
            tf = self._by_dir_name.get((os.path.dirname(f), name))
            if tf:
                return self.function_at(tf, name)
            return None
        if root in sf.bindings:
            spec = sf.bindings[root]
            tgt = self.idx.resolve(sf, spec)
            if not tgt:
                return None
            if ":" in spec and not members:  # from x import f / import { f }
                tgt2, rest = self.follow(tgt, [spec.split(":")[1]])
                return self.function_at(tgt2, rest[0]) if rest else (tgt2, "<module>")
            if members:
                tgt2, rest = self.follow(tgt, [root] + list(members))
                if tgt2 == tgt and rest and rest[0] == root:
                    rest = list(members)  # the binding is the module itself, not a re-exported name
            else:
                tgt2, rest = self.follow(tgt, [root])
            if rest:
                k = self.function_at(tgt2, rest[0])
                if k: return k
            if not members:
                return self.function_at(tgt, "<default>") or (tgt, "<module>")
            return self.function_at(tgt2, "<default>") or (tgt2, "<module>")
        if members and not root[:1].isupper():
            k = self.function_at(f, members[0])
            if k and root not in sf.bindings:
                return k
        return None

    def _edges(self, sf):
        root = sf.tree.root_node
        for n in walk(root):
            if n.type not in CALL_TYPES:
                continue
            fn = n.child_by_field_name("function") or n.child_by_field_name("constructor")
            if fn is None and n.type == "method_invocation":
                obj = n.child_by_field_name("object"); nm = n.child_by_field_name("name")
                txt = (sf.node_text(obj) + "." if obj is not None else "") + (sf.node_text(nm) if nm is not None else "")
            elif fn is None and n.type == "invocation_expression":
                txt = sf.node_text(n.children[0]) if n.children else ""
            elif fn is None:
                continue
            else:
                txt = sf.node_text(fn)
            txt = re.sub(r"\s+", "", txt)
            txt = txt.split("(")[0] if "(" in txt else txt
            parts = [p for p in re.split(r"[.?!]+", txt) if p and re.match(r"^\w+$", p)]
            if not parts:
                continue
            target = self._resolve(sf, parts[0], parts[1:])
            if target is None:
                continue
            caller = self.enclosing(sf.path, sf.line(n))
            if caller == target:
                continue
            self.calls.setdefault(caller, set()).add(target)

    # ------------------------------------------------------------ queries
    def reach(self, start, depth=8):
        out = []; seen = {start}; q = deque([(start, 0)])
        while q:
            cur, d = q.popleft()
            out.append(cur)
            if d >= depth:
                continue
            for nx in sorted(self.calls.get(cur, ())):
                if nx not in seen:
                    seen.add(nx); q.append((nx, d + 1))
        return out
