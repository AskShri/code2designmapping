"""Class index and function-level call graph (JavaScript/TypeScript, Python, Go, Java, C#).

ClassIndex records classes, their bases and typed fields (constructor-injected services, repositories).
CallGraph keys functions by (file, qualified name) -- "Class.method" inside a class, "<module>" for
module-level code -- and resolves calls through import bindings, re-exports, typed fields
(`this.userService.find()`), interface implementations, Go import paths and same-package lookup.
Detectors can add edges the syntax does not show (dependency injection hooks) as `call_edge` facts.
"""
import os, re
from collections import deque
from .index import walk, JS_LANGS

CLASS_TYPES = {
    "javascript": ("class_declaration", "class"), "typescript": ("class_declaration", "class", "abstract_class_declaration", "interface_declaration"),
    "tsx": ("class_declaration", "class", "abstract_class_declaration", "interface_declaration"),
    "python": ("class_definition",),
    "java": ("class_declaration", "interface_declaration", "record_declaration", "enum_declaration"),
    "c_sharp": ("class_declaration", "interface_declaration", "record_declaration", "struct_declaration"),
    "go": (),
}
FUNC_TYPES = {
    "javascript": ("function_declaration", "function_expression", "arrow_function", "method_definition", "generator_function_declaration", "function"),
    "python": ("function_definition", "lambda"),
    "go": ("function_declaration", "method_declaration", "func_literal"),
    "java": ("method_declaration", "constructor_declaration", "lambda_expression"),
    "c_sharp": ("method_declaration", "constructor_declaration", "local_function_statement", "lambda_expression"),
}
FUNC_TYPES["typescript"] = FUNC_TYPES["tsx"] = FUNC_TYPES["javascript"]
CALL_TYPES = ("call_expression", "call", "method_invocation", "invocation_expression", "object_creation_expression", "new_expression")
_FIELD_RX = {
    "typescript": re.compile(r"(?:private|public|protected|readonly)\s+(?:readonly\s+)?(\w+)\s*[?!]?\s*:\s*([\w.]+)(?:<\s*([\w.]+)[^>]*>)?"),
    "java": re.compile(r"(?:^|[;{}(,]|\n)\s*(?:@\w+(?:\([^)]*\))?\s*)*(?:private|protected|public)?\s*(?:static\s+)?(?:final\s+)?([A-Z][\w.]*)(?:<\s*([\w.]+)[^>]*>)?\s+(\w+)\s*(?=[;=,)])"),
    "c_sharp": re.compile(r"(?:^|[;{}(,]|\n)\s*(?:\[[^\]]*\]\s*)*(?:private|protected|public|internal)?\s*(?:static\s+)?(?:readonly\s+)?([A-Z][\w.]*)(?:<\s*([\w.]+)[^>]*>)?\??\s+(\w+)\s*(?=[;=,){])"),
}
_FIELD_RX["tsx"] = _FIELD_RX["javascript"] = _FIELD_RX["typescript"]


def _split_bases(header):
    """'extends A<B> implements C, D' or ': A<B>, C' -> [(name, first generic arg or None), ...]."""
    out = []
    header = re.sub(r"\bwhere\b.*$", "", header, flags=re.S)
    for m in re.finditer(r"([A-Za-z_][\w.]*)\s*(?:<\s*([\w.]+)[^>]*>)?", header):
        if m.group(1) in ("extends", "implements", "class", "interface", "record", "struct", "public", "private", "protected", "internal", "abstract", "final", "static", "sealed", "partial", "export", "default", "permits"):
            continue
        out.append((m.group(1).split(".")[-1], m.group(2).split(".")[-1] if m.group(2) else None))
    return out


class ClassIndex:
    def __init__(self, idx):
        self.idx = idx
        self.classes = {}    # (file, cls) -> dict(start, end, bases=[(name, generic)], decorators text before it)
        self.fields = {}     # (file, cls) -> {field: (type, generic)}
        self.impls = {}      # base type name -> sorted [(file, cls)]
        self._spans = {}     # file -> [(start, end, cls)] innermost-first
        for sf in idx.files.values():
            self._collect(sf)
        for k in self.impls:
            self.impls[k] = sorted(set(self.impls[k]))

    def _collect(self, sf):
        spans = []
        for n in walk(sf.tree.root_node):
            if n.type not in CLASS_TYPES.get(sf.lang, ()):
                continue
            nm = n.child_by_field_name("name")
            body = n.child_by_field_name("body")
            if nm is None:
                continue
            cls = sf.node_text(nm)
            head_end = body.start_byte if body is not None else n.end_byte
            header = sf.bytes[nm.end_byte:head_end].decode("utf-8", errors="replace")
            if sf.lang == "python":
                sup = n.child_by_field_name("superclasses")
                header = sf.node_text(sup) if sup is not None else ""
            params = ""
            if sf.lang == "c_sharp" and "(" in header.split(":")[0]:   # primary constructor parameters
                params = header[header.index("("):header.index(")") + 1] if ")" in header else ""
                header = header.replace(params, "")
            if sf.lang in ("java",) and header.lstrip().startswith("("):  # record components
                params = header[:header.index(")") + 1] if ")" in header else ""
                header = header.replace(params, "")
            bases = _split_bases(header) if sf.lang != "python" else [(b.strip().split("(")[0].split(".")[-1], None) for b in header.strip("()").split(",") if b.strip() and "=" not in b]
            key = (sf.path, cls)
            self.classes[key] = dict(start=sf.line(n), end=sf.end_line(n), bases=bases, header=header.strip())
            spans.append((sf.line(n), sf.end_line(n), cls))
            for b, _g in bases:
                self.impls.setdefault(b, []).append(key)
            rx = _FIELD_RX.get(sf.lang)
            fields = {}
            if rx is not None:
                text = params + "\n" + sf.node_text(n)
                for m in rx.finditer(text):
                    if sf.lang in JS_LANGS:
                        name, typ, gen = m.group(1), m.group(2), m.group(3)
                    else:
                        typ, gen, name = m.group(1), m.group(2), m.group(3)
                    if typ in ("return", "new", "throw", "else", "var", "await", "yield", "String", "Integer", "Boolean", "Long", "int", "string", "bool"):
                        continue
                    fields.setdefault(name, (typ.split(".")[-1], gen.split(".")[-1] if gen else None))
            self.fields[key] = fields
        spans.sort(key=lambda s: (s[1] - s[0], s[0]))
        self._spans[sf.path] = spans

    def class_at(self, file, line):
        for s, e, cls in self._spans.get(file, ()):
            if s <= line <= e:
                return cls
        return None

    def field_type(self, file, cls, name):
        """(type, generic arg) of a field, searching base classes declared in the repo."""
        seen = set()
        todo = [(file, cls)]
        while todo:
            key = todo.pop(0)
            if key in seen or key not in self.classes:
                continue
            seen.add(key)
            hit = self.fields.get(key, {}).get(name) or self.fields.get(key, {}).get("_" + name) or self.fields.get(key, {}).get(name.lstrip("_"))
            if hit:
                return hit
            for b, _g in self.classes[key]["bases"]:
                todo += [k for k in self.classes if k[1] == b]
        return None

    def base_generic(self, file, cls, base_names):
        """First generic argument of a base whose name is in base_names (e.g. JpaRepository<Owner, Integer> -> Owner)."""
        for b, g in self.classes.get((file, cls), {}).get("bases", ()):
            if b in base_names and g:
                return g
        return None


class CallGraph:
    def __init__(self, idx, classes=None, extra_edges=()):
        self.idx = idx
        self.classes = classes or ClassIndex(idx)
        self.functions = {}       # (file, qualname) -> (start_line, end_line)
        self.calls = {}           # key -> set(keys)
        self._spans = {}          # file -> [(start, end, qualname)] innermost-first
        self._by_dir = {}         # (dir, bare name) -> sorted [keys]   (Go / Java / C# package lookup)
        self.reexports = {}       # file -> {exported name: target file | [files]}
        for sf in idx.files.values():
            self._collect(sf)
            self._collect_reexports(sf)
        for k in self._by_dir:
            self._by_dir[k] = sorted(set(self._by_dir[k]))
        for sf in idx.files.values():
            self._edges(sf)
        for file, line, tfile, tsym in sorted(extra_edges):
            if file not in idx.files or tfile not in idx.files:
                continue
            target = self.function_at(tfile, tsym)
            if target:
                caller = self.enclosing(file, line)
                if caller != target:
                    self.calls.setdefault(caller, set()).add(target)

    # ------------------------------------------------------------ collection
    def _raw_name(self, sf, n):
        t = n.type
        if t in ("function_declaration", "generator_function_declaration", "method_definition", "function_definition", "method_declaration", "constructor_declaration", "local_function_statement"):
            nm = n.child_by_field_name("name")
            if nm is not None:
                return sf.node_text(nm)
        p = n.parent
        hops = 0
        while p is not None and p.type in ("arguments", "call_expression", "parenthesized_expression", "await_expression") and hops < 4:
            p = p.parent; hops += 1    # const f = catchAsync(async (req, res) => ...) takes the declarator's name
        if p is None:
            return None
        if p.type == "variable_declarator":
            nm = p.child_by_field_name("name")
            return sf.node_text(nm) if nm is not None and nm.type == "identifier" else None
        if p.type == "assignment_expression":
            left = sf.node_text(p.child_by_field_name("left"))
            if left == "module.exports":
                return "<default>"
            return left.split(".")[-1] if re.match(r"^[\w.]+$", left) else None
        if p.type in ("pair", "public_field_definition", "field_definition", "property_definition"):
            k = p.child_by_field_name("key") or p.child_by_field_name("name") or p.child_by_field_name("property")
            return sf.node_text(k).strip("'\"") if k is not None else None
        if p.type == "export_statement":
            return "<default>"
        if p.type == "assignment" and sf.lang == "python":
            left = p.child_by_field_name("left")
            return sf.node_text(left) if left is not None and left.type == "identifier" else None
        return None

    def _collect(self, sf):
        spans = [(1, len(sf.lines), "<module>")]
        self.functions[(sf.path, "<module>")] = (1, len(sf.lines))
        taken = {}
        ftypes = FUNC_TYPES.get(sf.lang, ())
        d = os.path.dirname(sf.path)
        for n in walk(sf.tree.root_node):
            if n.type not in ftypes:
                continue
            span = (sf.line(n), sf.end_line(n))
            name = self._raw_name(sf, n)
            cls = None
            if sf.lang == "go" and n.type == "method_declaration":
                recv = n.child_by_field_name("receiver")
                m = re.search(r"\*?\s*(\w+)\s*\)?\s*$", sf.node_text(recv).rstrip(")")) if recv is not None else None
                cls = m.group(1) if m else None
            elif name and n.type in ("method_definition", "method_declaration", "constructor_declaration", "function_definition", "public_field_definition") or (name and n.parent is not None and n.parent.type in ("public_field_definition", "field_definition", "property_definition")):
                cls = self.classes.class_at(sf.path, span[0])
                if sf.lang == "python" and cls:
                    # only direct methods of the class, not functions nested in methods
                    p = n.parent
                    while p is not None and p.type in ("block", "decorated_definition"):
                        p = p.parent
                    if p is None or p.type != "class_definition":
                        cls = None
            anon = name is None
            qual = f"<anon:{span[0]}>" if anon else (f"{cls}.{name}" if cls else name)
            if span in taken:
                prev = taken[span]
                if anon or not prev.startswith("<anon"):
                    continue   # same span already has an equal or better name
                del self.functions[(sf.path, prev)]
                spans[:] = [s for s in spans if not (s[0] == span[0] and s[1] == span[1] and s[2] == prev)]
            if (sf.path, qual) in self.functions:
                qual = f"{qual}#{sum(1 for k in self.functions if k[0] == sf.path and k[1].split('#')[0] == qual) + 1}"
            self.functions[(sf.path, qual)] = span
            taken[span] = qual
            spans.append((span[0], span[1], qual))
            if not anon:
                self._by_dir.setdefault((d, name), []).append((sf.path, qual))
        spans.sort(key=lambda s: (s[1] - s[0], s[0]))
        self._spans[sf.path] = spans

    def _collect_reexports(self, sf):
        if sf.lang not in JS_LANGS:
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
        stars = [self.idx.resolve(sf, m.group(1)) for m in re.finditer(r"export\s*\*\s*from\s*['\"]([^'\"]+)['\"]", sf.text)]
        stars = [t for t in stars if t]
        if stars:
            rx["*"] = stars
        obj = re.search(r"module\.exports\s*=\s*\{([^}]*)\}", sf.text)
        if obj:
            for nm in obj.group(1).split(","):
                nm = nm.strip().split(":")[0].strip()
                if nm in sf.bindings:
                    t = self.idx.resolve(sf, sf.bindings[nm])
                    if t: rx.setdefault(nm, t)
        if rx:
            self.reexports[sf.path] = rx

    # ------------------------------------------------------------ lookup
    def enclosing(self, file, line):
        for s, e, name in self._spans.get(file, ()):
            if s <= line <= e:
                return (file, name)
        return (file, "<module>")

    def function_at(self, file, name):
        """Function key for a (possibly bare) name in a file: exact, then `Class.name`, then `name#n`."""
        if file is None or name is None:
            return None
        if (file, name) in self.functions:
            return (file, name)
        hits = sorted(k for k in self.functions if k[0] == file and (k[1].split("#")[0] == name or k[1].split("#")[0].endswith("." + name)))
        return hits[0] if hits else None

    def function_by_span(self, file, start, end):
        """The function that is exactly (or most nearly) the span start..end: an inline handler."""
        spans = self._spans.get(file, ())
        exact = [n for s_, e_, n in spans if s_ == start and e_ == end and n != "<module>"]
        if exact:
            return (file, exact[0])
        inside = sorted(((e_ - s_, n) for s_, e_, n in spans if s_ >= start and e_ <= end and n != "<module>"), reverse=True)
        if inside:
            return (file, inside[0][1])
        return self.enclosing(file, start)

    def functions_in(self, file, cls=None):
        return sorted(k for k in self.functions if k[0] == file and not k[1].startswith("<") and (cls is None or k[1].startswith(cls + ".")))

    def follow(self, file, members):
        """Follow re-exports: (controllers/index.js, ['authController', 'register']) -> (auth.controller.js, ['register'])."""
        for _ in range(4):
            rx = self.reexports.get(file)
            if not rx or not members:
                break
            hit = rx.get(members[0])
            if isinstance(hit, str):
                file, members = hit, members[1:]
                continue
            star = next((t for t in rx.get("*", []) if self.function_at(t, members[0]) or members[0] in self.reexports.get(t, {})), None)
            if star is None:
                break
            file = star
        return file, members

    def resolve_ref(self, sf, text, line=1):
        """Resolve a handler reference ('ctrl.register', 'views.index', 'svc.homeHandler') to a function key."""
        parts = [p for p in re.split(r"[.?!]+", re.sub(r"\s+", "", text).split("(")[0]) if re.match(r"^\w+$", p)]
        if not parts:
            return None
        hits = self._resolve(sf, self.classes.class_at(sf.path, line), parts)
        return hits[0] if hits else None

    def type_method(self, sf, type_name, method):
        """Keys of `method` on a type: the declaring class, else every implementation of the interface."""
        out = []
        tf = self.idx.type_file(sf, type_name)
        if tf:
            k = (tf, f"{type_name}.{method}")
            if k in self.functions:
                out.append(k)
        if not out:
            for (f, cls) in self.classes.impls.get(type_name, ()):
                k = (f, f"{cls}.{method}")
                if k in self.functions:
                    out.append(k)
        if not out and tf:   # inherited from a base class in the repo
            for b, _g in self.classes.classes.get((tf, type_name), {}).get("bases", ()):
                out += self.type_method(sf, b, method)
        return sorted(set(out))

    def _go_field_type(self, d, typ, field):
        """Type name of `field` in Go struct `typ` declared in package directory d (pointer and package stripped)."""
        if not hasattr(self, "_go_structs"):
            self._go_structs = {}
            for path, gsf in self.idx.files.items():
                if gsf.lang != "go":
                    continue
                for m in re.finditer(r"^type\s+(\w+)\s+struct\s*\{(.*?)^\}", gsf.text, re.M | re.S):
                    fields = {}
                    for fm in re.finditer(r"^\s*(\w+(?:\s*,\s*\w+)*)\s+\*?(?:\[\])?(?:\w+\.)?(\w+)", m.group(2), re.M):
                        for name in re.split(r"\s*,\s*", fm.group(1)):
                            fields[name] = fm.group(2)
                    self._go_structs[(os.path.dirname(path), m.group(1))] = fields
            self.files_lang = {p: x.lang for p, x in self.idx.files.items()}
        return self._go_structs.get((d, typ), {}).get(field)

    def _resolve(self, sf, cls, parts):
        f = sf.path
        root, members = parts[0], parts[1:]
        if root in ("this", "self", "cls", "base", "super"):
            if not members:
                return []
            if len(members) >= 2 and cls:
                ft = self.classes.field_type(f, cls, members[0])
                if ft:
                    return self.type_method(sf, ft[0], members[1])
            if cls:
                k = self.function_at(f, f"{cls}.{members[0]}")
                if k: return [k]
                for b, _g in self.classes.classes.get((f, cls), {}).get("bases", ()):
                    hits = self.type_method(sf, b, members[0])
                    if hits: return hits
            k = self.function_at(f, members[0])
            return [k] if k else []
        if sf.lang == "go":
            if members and sf.go_imports.get(root):
                return list(self._by_dir.get((sf.go_imports[root], members[0]), []))[:3]
            if members and root in sf.go_imports:
                return []                      # external package
            cands = self._by_dir.get((os.path.dirname(f), members[-1] if members else root), [])
            if members:
                if len(members) == 2 and cls:   # h.store.List(): a field of the receiver's struct type
                    ftype = self._go_field_type(os.path.dirname(f), cls, members[0])
                    if ftype:
                        exact = sorted(k for k in self.functions if k[1] == f"{ftype}.{members[1]}")
                        if exact:
                            return exact[:3]
                        impl = sorted(k for k in self.functions if k[1].endswith("." + members[1]) and self.files_lang.get(k[0]) == "go")
                        return impl[:3] if len(impl) <= 3 else []     # an interface field: its implementations
                if len(members) > 1:
                    return []                  # a.b.c(): a field of another type, not a package-local method
                return [k for k in cands if "." in k[1]][:3]
            return [k for k in cands if "." not in k[1]][:3]
        if not members:
            if cls:
                k = self.function_at(f, f"{cls}.{root}")
                if k: return [k]
            if (f, root) in self.functions:
                return [(f, root)]
        if cls and members:                      # field access without `this` (Java, C#)
            ft = self.classes.field_type(f, cls, root)
            if ft:
                return self.type_method(sf, ft[0], members[0])
        if root in sf.bindings and sf.lang in JS_LANGS:
            tgt = self.idx.resolve(sf, sf.bindings[root])
            if not tgt:
                return []
            if members:
                tgt2, rest = self.follow(tgt, [root] + list(members))
                if tgt2 == tgt and rest and rest[0] == root:
                    rest = list(members)
            else:
                tgt2, rest = self.follow(tgt, [root])
            if rest:
                k = self.function_at(tgt2, rest[0])
                if k: return [k]
                if len(rest) >= 2:             # Class.staticMethod / namespace.fn
                    k = self.function_at(tgt2, rest[-1])
                    if k: return [k]
            if not members:
                return [self.function_at(tgt, "<default>") or (tgt, "<module>")]
            return [self.function_at(tgt2, "<default>") or (tgt2, "<module>")]
        if root in sf.bindings and sf.lang == "python":
            tfile, sym = self.idx.resolve_symbol(sf, sf.bindings[root])
            if not tfile:
                return []
            name = members[-1] if members else sym
            if sym and members:                 # imported class or object: Class.method / obj.method
                k = self.function_at(tfile, f"{sym}.{members[0]}") or self.function_at(tfile, members[0])
                return [k] if k else []
            k = self.function_at(tfile, name) if name else None
            return [k] if k else ([(tfile, "<module>")] if not members and not sym else [])
        if sf.lang in ("java", "c_sharp") or (sf.lang in JS_LANGS and root[:1].isupper()):
            if members and self.idx.type_file(sf, root):
                return self.type_method(sf, root, members[0])          # static call or constructor-less type access
            if sf.lang in ("java", "c_sharp") and not members:
                return list(self._by_dir.get((os.path.dirname(f), root), []))[:3]
        if not members:
            k = self.function_at(f, root)
            return [k] if k else []
        return []

    # ------------------------------------------------------------ edges
    def _callee_text(self, sf, n):
        fn = n.child_by_field_name("function") or n.child_by_field_name("constructor") or n.child_by_field_name("type")
        if n.type == "method_invocation":
            obj = n.child_by_field_name("object"); nm = n.child_by_field_name("name")
            return (sf.node_text(obj) + "." if obj is not None else "") + (sf.node_text(nm) if nm is not None else "")
        if fn is None and n.type == "invocation_expression" and n.children:
            return sf.node_text(n.children[0])
        return sf.node_text(fn) if fn is not None else ""

    def _edges(self, sf):
        for n in walk(sf.tree.root_node):
            if n.type not in CALL_TYPES:
                continue
            txt = re.sub(r"\s+", "", self._callee_text(sf, n))
            txt = re.sub(r"<[^<>()]*>", "", txt)            # generic arguments
            if not txt:
                continue
            # for chains like a.b().c() resolve the head a.b; the last segment of a plain a.b.c is the callee
            head = txt.split("(")[0]
            parts = [p for p in re.split(r"[.?!]+", head) if re.match(r"^\w+$", p)]
            if not parts:
                continue
            line = sf.line(n)
            caller = self.enclosing(sf.path, line)
            cls = self.classes.class_at(sf.path, line)
            if sf.lang == "go" and "." in caller[1]:
                cls = caller[1].split(".")[0]            # Go: the receiver type of the enclosing method
            for target in self._resolve(sf, cls, parts):
                if target and target != caller:
                    self.calls.setdefault(caller, set()).add(target)

    # ------------------------------------------------------------ queries
    def reach(self, start, depth=8):
        """Functions reachable from `start` in BFS order (deterministic: sorted neighbours)."""
        out = []; seen = {start}; q = deque([(start, 0)])
        while q:
            cur, d = q.popleft()
            out.append(cur)
            if d >= depth:
                continue
            for nx in sorted(self.calls.get(cur, ())):
                if nx not in seen:
                    seen.add(nx); q.append((nx, d + 1))
                for impl in self.implementations(nx):     # an interface or abstract method runs one of its implementations
                    if impl not in seen:
                        seen.add(impl); q.append((impl, d + 1))
        return out

    def implementations(self, key):
        """(file, 'IFace.m') -> [(impl file, 'Impl.m')] for classes in the repository that implement or extend IFace."""
        f, name = key
        if "." not in name or self.classes is None:
            return []
        cls, meth = name.split(".", 1)
        out = []
        for ifile, icls in self.classes.impls.get(cls, ()):
            k = (ifile, f"{icls}.{meth}")
            if k in self.functions and k != key:
                out.append(k)
        return out
