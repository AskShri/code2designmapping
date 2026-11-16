"""Repository index: deterministic file walk, language detection, tree-sitter parsing, and import
resolution (relative imports, tsconfig path aliases, Python packages, Go import paths, Java/C# types)."""
import fnmatch, json, os, re
from collections import OrderedDict
import tree_sitter, tree_sitter_javascript, tree_sitter_typescript, tree_sitter_python, tree_sitter_go, tree_sitter_java, tree_sitter_c_sharp

LANGS = {
    "javascript": tree_sitter.Language(tree_sitter_javascript.language()),
    "typescript": tree_sitter.Language(tree_sitter_typescript.language_typescript()),
    "tsx": tree_sitter.Language(tree_sitter_typescript.language_tsx()),
    "python": tree_sitter.Language(tree_sitter_python.language()),
    "go": tree_sitter.Language(tree_sitter_go.language()),
    "java": tree_sitter.Language(tree_sitter_java.language()),
    "c_sharp": tree_sitter.Language(tree_sitter_c_sharp.language()),
}
JS_LANGS = ("javascript", "typescript", "tsx")
EXT_LANG = {".js": "javascript", ".mjs": "javascript", ".cjs": "javascript", ".jsx": "javascript",
            ".ts": "typescript", ".mts": "typescript", ".cts": "typescript", ".tsx": "tsx",
            ".py": "python", ".go": "go", ".java": "java", ".cs": "c_sharp"}
UNSUPPORTED_SOURCE = {".kt", ".rb", ".php", ".rs", ".scala", ".swift", ".c", ".cc", ".cpp", ".ex", ".exs", ".dart"}
IGNORE_DIRS = {"node_modules", ".git", "dist", "build", "vendor", ".next", "coverage", "__pycache__", ".venv", "venv", "env", "target", "bin", "obj",
               ".idea", ".vscode", "third_party", "site-packages", "bower_components", ".cache", "out", "migrations", "Migrations", "wwwroot", ".code2design"}
TEST_RX = re.compile(r"(^|/)(serviceWorker|registerServiceWorker|reportWebVitals|setupTests)\.[jt]sx?$"
                     r"|(^|/)(tests?|__tests__|spec|specs|e2e|fixtures?|mocks?|__mocks__|testdata|UnitTests|IntegrationTests|FunctionalTests)(/|$)"
                     r"|\.(test|spec|e2e-spec)\.[jt]sx?$|_test\.py$|(^|/)test_[^/]*\.py$|(^|/)conftest\.py$|_test\.go$|Tests?\.(java|cs)$"
                     r"|\.pb\.go$|_pb2(_grpc)?\.py$|\.g\.cs$|\.Designer\.cs$|\.min\.js$|\.bundle\.js$|(^|/)[^/]*Tests/")
CONFIG_PREFIXES = ("docker-compose", "compose.yaml", "compose.yml", "Dockerfile", "package.json", "schema.prisma", "serverless.yml", "requirements", "pyproject.toml", "go.mod", "pom.xml", "build.gradle",
                   "application.properties", "application.yml", "application.yaml", "appsettings.json", "ormconfig")
_parsers = {k: tree_sitter.Parser(v) for k, v in LANGS.items()}


class SourceFile:
    def __init__(self, root, rel, lang):
        self.path = rel
        self.lang = lang
        with open(os.path.join(root, rel), "rb") as fh:
            self.bytes = fh.read()
        self.text = self.bytes.decode("utf-8", errors="replace")
        self.lines = self.text.splitlines() or [""]
        self.tree = _parsers[lang].parse(self.bytes)
        self.is_test = bool(TEST_RX.search(rel))
        self.imports = []          # (spec, line, local_names)
        self.bindings = {}         # local identifier -> module spec ("pkg", "./rel", "pkg:name" for Python from-imports)
        self.go_imports = {}       # Go: alias -> repo dir (None when external)
        self.package = None        # Java package / C# namespace

    def node_text(self, node):
        return self.bytes[node.start_byte:node.end_byte].decode("utf-8", errors="replace")

    def line(self, node):
        return node.start_point[0] + 1

    def end_line(self, node):
        return node.end_point[0] + 1

    def line_of_offset(self, offset):
        return self.text.count("\n", 0, offset) + 1


def walk(node):
    """Pre-order traversal of a tree-sitter node."""
    stack = [node]
    while stack:
        n = stack.pop()
        yield n
        stack.extend(reversed(n.children))


def _load_jsonc(path):
    try:
        text = open(path, encoding="utf-8", errors="replace").read()
    except OSError:
        return None
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    text = re.sub(r"(^|[^:\"'])//[^\n]*", r"\1", text)
    text = re.sub(r",(\s*[}\]])", r"\1", text)
    try:
        return json.loads(text)
    except ValueError:
        return None


class RepoIndex:
    def __init__(self, root, include=None, exclude=None):
        self.root = os.path.abspath(root)
        self.files = OrderedDict()      # rel path -> SourceFile, in sorted order
        self.unsupported = []           # (rel, reason)
        self.config_files = []
        self.k8s_files = []
        self.tf_files = []
        self.counts = {}
        self.include = include or ["**"]
        self.exclude = exclude or []
        self.types = {}                 # (lang, simple type name) -> sorted [files]   (Java / C# / TS classes)
        self._tsconfigs = {}            # dir -> (baseUrl dir, [(pattern, [targets])]) or None
        self._go_dirs = None
        self._scan()
        self.config_files = sorted(set(self.config_files))
        self.k8s_files = sorted(set(self.k8s_files))
        self.tf_files = sorted(set(self.tf_files))
        for sf in self.files.values():
            self._index_imports(sf)
        self._index_types()

    # ------------------------------------------------------------ scan
    def _wanted(self, rel):
        if any(fnmatch.fnmatch(rel, p) for p in self.exclude):
            return False
        return any(p == "**" or fnmatch.fnmatch(rel, p) for p in self.include)

    def _scan(self):
        for dirpath, dirnames, filenames in os.walk(self.root):
            dirnames[:] = sorted(d for d in dirnames if d not in IGNORE_DIRS and (not d.startswith(".") or d in (".github",)))
            for fn in sorted(filenames):
                rel = os.path.relpath(os.path.join(dirpath, fn), self.root).replace(os.sep, "/")
                if not self._wanted(rel):
                    continue
                ext = os.path.splitext(fn)[1].lower()
                full = os.path.join(self.root, rel)
                if fn.startswith(CONFIG_PREFIXES) or fn.endswith((".prisma", ".csproj")) or (fn.startswith(".env") and not fn.endswith(".d.ts")):
                    self.config_files.append(rel)
                if ext == ".tf":
                    if not rel.startswith(".github/"):     # CI scaffolding is not the system's deployment
                        self.tf_files.append(rel)
                    continue
                if ext in (".yml", ".yaml"):
                    if not fn.startswith(("docker-compose", "compose", "application")):
                        try:
                            with open(full, "r", encoding="utf-8", errors="replace") as fh:
                                head = fh.read(6000)
                            if re.search(r"^kind:\s*(Deployment|Service|StatefulSet|DaemonSet|Ingress|Job|CronJob)\b", head, re.M):
                                self.k8s_files.append(rel)
                        except OSError:
                            pass
                    continue
                if ext in EXT_LANG:
                    if fn.endswith(".d.ts"):
                        continue
                    try:
                        if os.path.getsize(full) > 1_500_000:
                            self.unsupported.append((rel, "file too large")); continue
                        sf = SourceFile(self.root, rel, EXT_LANG[ext])
                    except Exception as e:  # noqa: BLE001 - unreadable file is a coverage gap, not a crash
                        self.unsupported.append((rel, f"unreadable: {type(e).__name__}")); continue
                    self.files[rel] = sf
                    self.counts[sf.lang] = self.counts.get(sf.lang, 0) + 1
                elif ext in UNSUPPORTED_SOURCE:
                    self.unsupported.append((rel, f"no recognizer for {ext}"))

    # ------------------------------------------------------------ imports
    def _index_imports(self, sf):
        if sf.lang == "python":
            self._py_imports(sf)
        elif sf.lang in JS_LANGS:
            self._js_imports(sf)
        elif sf.lang == "go":
            self._go_imports(sf)
        elif sf.lang == "java":
            m = re.search(r"^\s*package\s+([\w.]+)\s*;", sf.text, re.M); sf.package = m.group(1) if m else None
            for m in re.finditer(r"^\s*import\s+(?:static\s+)?([\w.]+)\s*;", sf.text, re.M):
                spec = m.group(1); sf.imports.append((spec, sf.line_of_offset(m.start()), [spec.split(".")[-1]])); sf.bindings[spec.split(".")[-1]] = spec
        elif sf.lang == "c_sharp":
            m = re.search(r"^\s*namespace\s+([\w.]+)", sf.text, re.M); sf.package = m.group(1) if m else None
            for m in re.finditer(r"^\s*(?:global\s+)?using\s+(?:static\s+)?([\w.]+)\s*;", sf.text, re.M):
                sf.imports.append((m.group(1), sf.line_of_offset(m.start()), []))

    def _js_imports(self, sf):
        for n in walk(sf.tree.root_node):
            if n.type == "import_statement":
                src = n.child_by_field_name("source")
                if src is None:
                    continue
                spec = sf.node_text(src).strip("'\"`")
                names = []
                for c in walk(n):
                    if c.type == "identifier" and c.parent is not None and c.parent.type in ("import_clause", "namespace_import"):
                        names.append(sf.node_text(c))
                    elif c.type == "import_specifier":
                        alias = c.child_by_field_name("alias") or c.child_by_field_name("name")
                        if alias is not None:
                            names.append(sf.node_text(alias))
                names = sorted(set(names))
                sf.imports.append((spec, sf.line(n), names))
                for nm in names:
                    sf.bindings[nm] = spec
            elif n.type == "call_expression":
                fn = n.child_by_field_name("function"); args = n.child_by_field_name("arguments")
                if fn is None or args is None or sf.node_text(fn) != "require" or not args.named_child_count:
                    continue
                a0 = args.named_children[0]
                if a0.type not in ("string", "template_string"):
                    continue
                spec = sf.node_text(a0).strip("'\"`")
                names = []
                p = n.parent
                while p is not None and p.type in ("member_expression", "call_expression", "parenthesized_expression", "await_expression"):
                    p = p.parent
                if p is not None and p.type == "variable_declarator":
                    nm = p.child_by_field_name("name")
                    if nm is not None and nm.type == "identifier":
                        names.append(sf.node_text(nm))
                    elif nm is not None:
                        names += [sf.node_text(c) for c in walk(nm) if c.type in ("shorthand_property_identifier_pattern", "identifier")]
                names = sorted(set(names))
                sf.imports.append((spec, sf.line(n), names))
                for nm in names:
                    sf.bindings[nm] = spec

    def _py_imports(self, sf):
        for n in walk(sf.tree.root_node):
            if n.type == "import_statement":
                for c in n.named_children:
                    if c.type == "dotted_name":
                        spec = sf.node_text(c); local = spec.split(".")[0]
                        sf.imports.append((spec, sf.line(n), [local])); sf.bindings[local] = spec if "." not in spec else local
                        sf.bindings.setdefault(spec, spec)
                    elif c.type == "aliased_import":
                        nm = c.child_by_field_name("name"); al = c.child_by_field_name("alias")
                        spec = sf.node_text(nm); local = sf.node_text(al) if al is not None else spec.split(".")[0]
                        sf.imports.append((spec, sf.line(n), [local])); sf.bindings[local] = spec
            elif n.type == "import_from_statement":
                mod = n.child_by_field_name("module_name")
                spec = sf.node_text(mod) if mod is not None else "."
                names = []
                for c in n.named_children[1:]:
                    if c.type == "dotted_name":
                        names.append((sf.node_text(c), sf.node_text(c)))
                    elif c.type == "aliased_import":
                        nm = c.child_by_field_name("name"); al = c.child_by_field_name("alias")
                        names.append((sf.node_text(nm), sf.node_text(al) if al is not None else sf.node_text(nm)))
                sf.imports.append((spec, sf.line(n), [local for _, local in names]))
                for orig, local in names:
                    sf.bindings[local] = spec + ":" + orig

    def _go_imports(self, sf):
        if self._go_dirs is None:
            self._go_dirs = sorted({os.path.dirname(p) for p in self.files if p.endswith(".go")} | set())
        m = re.search(r"^\s*package\s+(\w+)", sf.text, re.M); sf.package = m.group(1) if m else None
        for m in re.finditer(r"^\s*(?:import\s+)?(?:([\w.]+)\s+)?\"([^\"]+)\"\s*$", sf.text, re.M):
            alias, path = m.group(1), m.group(2)
            if "/" not in path and "." not in path and not alias:
                local = path
            else:
                local = alias or path.split("/")[-1]
            # match the longest repo dir that is a suffix of the import path
            best = None
            for d in self._go_dirs:
                if d and (path == d or path.endswith("/" + d)) and (best is None or len(d) > len(best)):
                    best = d
            sf.go_imports[local] = best
            sf.imports.append((path, sf.line_of_offset(m.start(2)), [local]))
            sf.bindings[local] = path

    def _index_types(self):
        rx = {"java": re.compile(r"\b(?:class|interface|record|enum)\s+(\w+)"),
              "c_sharp": re.compile(r"\b(?:class|interface|record|struct)\s+(\w+)"),
              "typescript": re.compile(r"\b(?:class|interface)\s+(\w+)"), "tsx": re.compile(r"\b(?:class|interface)\s+(\w+)")}
        for sf in self.files.values():
            r = rx.get(sf.lang)
            if not r:
                continue
            lang = "typescript" if sf.lang == "tsx" else sf.lang
            for m in r.finditer(sf.text):
                self.types.setdefault((lang, m.group(1)), [])
                if sf.path not in self.types[(lang, m.group(1))]:
                    self.types[(lang, m.group(1))].append(sf.path)

    # ------------------------------------------------------------ resolution
    def resolve(self, sf, spec):
        """Resolve an import spec to a repo-relative source file, or None for external packages."""
        if spec is None:
            return None
        if sf.lang == "python":
            return self.resolve_symbol(sf, spec)[0]
        if sf.lang not in JS_LANGS:
            return None
        if spec.startswith("."):
            return self._js_candidates(os.path.normpath(os.path.join(os.path.dirname(sf.path), spec)).replace(os.sep, "/"))
        return self._resolve_ts_alias(sf, spec)

    def _js_candidates(self, base):
        base = base.lstrip("./") if base.startswith("./") else base
        if base.endswith(".js") and base[:-3] + ".ts" in self.files:
            return base[:-3] + ".ts"
        cands = [base] + [base + e for e in (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs")] + [base + "/index" + e for e in (".ts", ".tsx", ".js", ".jsx", ".mjs")]
        for c in cands:
            if c in self.files:
                return c
        return None

    def _tsconfig_for(self, d):
        if d in self._tsconfigs:
            return self._tsconfigs[d]
        cfg = None
        for name in ("tsconfig.json", "jsconfig.json"):
            doc = _load_jsonc(os.path.join(self.root, d, name))
            if isinstance(doc, dict):
                co = doc.get("compilerOptions") or {}
                if "baseUrl" in co or "paths" in co:
                    base = os.path.normpath(os.path.join(d, co.get("baseUrl", "."))).replace(os.sep, "/")
                    cfg = ("" if base == "." else base, sorted((k, list(v)) for k, v in (co.get("paths") or {}).items() if isinstance(v, list)), "baseUrl" in co)
                    break
        if cfg is None and d not in ("", "."):
            cfg = self._tsconfig_for(os.path.dirname(d))
        self._tsconfigs[d] = cfg
        return cfg

    def _resolve_ts_alias(self, sf, spec):
        cfg = self._tsconfig_for(os.path.dirname(sf.path))
        if not cfg:
            return None
        base, paths, has_base = cfg
        for pattern, targets in paths:
            if "*" in pattern:
                pre, post = pattern.split("*", 1)
                if spec.startswith(pre) and spec.endswith(post) and len(spec) >= len(pre) + len(post):
                    star = spec[len(pre):len(spec) - len(post)] if post else spec[len(pre):]
                    for t in targets:
                        hit = self._js_candidates(os.path.normpath(os.path.join(base, t.replace("*", star))).replace(os.sep, "/"))
                        if hit:
                            return hit
            elif spec == pattern:
                for t in targets:
                    hit = self._js_candidates(os.path.normpath(os.path.join(base, t)).replace(os.sep, "/"))
                    if hit:
                        return hit
        if has_base:
            return self._js_candidates(os.path.normpath(os.path.join(base, spec)).replace(os.sep, "/"))
        return None

    def resolve_symbol(self, sf, spec):
        """Python: resolve a binding spec ("pkg.mod" or "pkg.mod:name") to (file, symbol or None).
        `from pkg import mod` resolves to the submodule file when one exists."""
        if spec is None:
            return (None, None)
        mod, _, name = spec.partition(":")
        base = self._py_module(sf, mod)
        if name:
            sub = self._py_module(sf, (mod.rstrip(".") + "." + name) if not mod.endswith(".") else mod + name)
            if sub:
                return (sub, None)
            return (base, name) if base else (None, None)
        return (base, None)

    def _py_module(self, sf, mod):
        if mod.startswith("."):
            dots = len(mod) - len(mod.lstrip("."))
            d = os.path.dirname(sf.path)
            for _ in range(dots - 1):
                d = os.path.dirname(d)
            rest = mod.lstrip(".")
            bases = [os.path.normpath(os.path.join(d, *rest.split("."))).replace(os.sep, "/") if rest else (d or ".")]
        else:
            parts = mod.split(".")
            roots = [""]
            d = os.path.dirname(sf.path)
            while d:
                roots.append(d); d = os.path.dirname(d)
            roots += ["src", "app"]
            bases = [os.path.normpath(os.path.join(r, *parts)).replace(os.sep, "/") for r in roots]
        for b in bases:
            for c in (b + ".py", b + "/__init__.py"):
                c = c.lstrip("./") if c.startswith("./") else c
                if c in self.files:
                    return c
        return None

    def type_file(self, sf, type_name):
        """Java / C# / TS: the file declaring a type, preferring an explicit import, then the same directory."""
        lang = "typescript" if sf.lang in JS_LANGS else sf.lang
        if sf.lang in JS_LANGS and type_name in sf.bindings:
            hit = self.resolve(sf, sf.bindings[type_name])
            if hit:
                return hit
        files = self.types.get((lang, type_name)) or []
        if not files:
            return None
        if sf.path in files:
            return sf.path
        d = os.path.dirname(sf.path)
        same = [f for f in files if os.path.dirname(f) == d]
        if same:
            return same[0]
        if sf.lang == "java" and type_name in sf.bindings:
            want = sf.bindings[type_name].replace(".", "/") + ".java"
            for f in files:
                if f.endswith(want):
                    return f
        return sorted(files, key=lambda f: (-len(os.path.commonprefix([f, sf.path])), f))[0]
