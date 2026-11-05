"""Repository index: file walk, language detection, tree-sitter parsing, import resolution."""
import os, re, fnmatch
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
EXT_LANG = {".js": "javascript", ".mjs": "javascript", ".cjs": "javascript", ".jsx": "javascript",
            ".ts": "typescript", ".mts": "typescript", ".cts": "typescript", ".tsx": "tsx", ".py": "python", ".go": "go", ".java": "java", ".cs": "c_sharp"}
UNSUPPORTED_SOURCE = {".kt", ".rb", ".php", ".rs", ".scala", ".swift", ".c", ".cc", ".cpp", ".h", ".ex", ".exs", ".dart"}
IGNORE_DIRS = {"node_modules", ".git", "dist", "build", "vendor", ".next", "coverage", "__pycache__", ".venv", "venv", "env", "target", "bin", "obj", ".idea", ".vscode", "third_party", "site-packages", "bower_components", ".cache", "out"}
TEST_RX = re.compile(r"(^|/)(serviceWorker|registerServiceWorker|reportWebVitals|setupTests)\.[jt]sx?$|(^|/)(tests?|__tests__|spec|specs|e2e|fixtures?|mocks?|__mocks__|testdata)(/|$)|\.(test|spec)\.[jt]sx?$|_test\.py$|(^|/)test_[^/]*\.py$|_test\.go$|Tests?\.(java|cs)$|\.pb\.go$|_pb2(_grpc)?\.py$|\.g\.cs$")
CONFIG_FILES = ("docker-compose", "compose.yaml", "compose.yml", "Dockerfile", "package.json", ".env", "schema.prisma", "serverless.yml", "requirements.txt", "pyproject.toml", "go.mod", "pom.xml", "build.gradle")

_parsers = {k: tree_sitter.Parser(v) for k, v in LANGS.items()}


class SourceFile:
    def __init__(self, root, rel, lang):
        self.path = rel
        self.lang = lang
        with open(os.path.join(root, rel), "rb") as fh:
            self.bytes = fh.read()
        self.text = self.bytes.decode("utf-8", errors="replace")
        self.lines = self.text.splitlines()
        self.tree = _parsers[lang].parse(self.bytes)
        self.is_test = bool(TEST_RX.search(rel))
        self.imports = []          # (spec, line, local_names)
        self.bindings = {}         # local identifier -> module spec

    def node_text(self, node):
        return self.bytes[node.start_byte:node.end_byte].decode("utf-8", errors="replace")

    def line(self, node):
        return node.start_point[0] + 1

    def end_line(self, node):
        return node.end_point[0] + 1


def walk(node):
    stack = [node]
    while stack:
        n = stack.pop()
        yield n
        stack.extend(reversed(n.children))


class RepoIndex:
    def __init__(self, root, include=None, exclude=None):
        self.root = os.path.abspath(root)
        self.files = OrderedDict()
        self.unsupported = []
        self.config_files = []
        self.k8s_files = []
        self.counts = {}
        self.include = include or ["**"]
        self.exclude = exclude or []
        self._scan()
        self.config_files = sorted(set(self.config_files))
        self.k8s_files = sorted(set(self.k8s_files))
        self._index_imports()

    def _wanted(self, rel):
        if self.exclude and any(fnmatch.fnmatch(rel, p) for p in self.exclude):
            return False
        return any(fnmatch.fnmatch(rel, p) or p == "**" for p in self.include)

    def _scan(self):
        for dirpath, dirnames, filenames in os.walk(self.root):
            dirnames[:] = sorted(d for d in dirnames if d not in IGNORE_DIRS and not d.startswith(".") or d in (".github",))
            for fn in sorted(filenames):
                rel = os.path.relpath(os.path.join(dirpath, fn), self.root)
                if not self._wanted(rel):
                    continue
                ext = os.path.splitext(fn)[1].lower()
                if fn.startswith(CONFIG_FILES) or fn in ("Dockerfile",) or fn.endswith((".prisma",)) or (fn.startswith(".env") and not fn.endswith(".d.ts")):
                    self.config_files.append(rel)
                if ext in (".yml", ".yaml"):
                    if fn.startswith(("docker-compose", "compose")):
                        self.config_files.append(rel)
                    else:
                        try:
                            with open(os.path.join(self.root, rel), "r", encoding="utf-8", errors="replace") as fh:
                                head = fh.read(4000)
                            if re.search(r"^kind:\s*(Deployment|Service|StatefulSet|DaemonSet|Ingress|Job|CronJob)\b", head, re.M):
                                self.k8s_files.append(rel)
                        except OSError:
                            pass
                    continue
                if ext in EXT_LANG:
                    if ext == ".ts" and fn.endswith(".d.ts"):
                        continue
                    if os.path.getsize(os.path.join(self.root, rel)) > 1_500_000:
                        self.unsupported.append((rel, "file too large"))
                        continue
                    try:
                        sf = SourceFile(self.root, rel, EXT_LANG[ext])
                    except Exception as e:  # noqa
                        self.unsupported.append((rel, f"parse error: {e}"))
                        continue
                    self.files[rel] = sf
                    self.counts[sf.lang] = self.counts.get(sf.lang, 0) + 1
                elif ext in UNSUPPORTED_SOURCE:
                    self.unsupported.append((rel, f"no recognizer for {ext}"))

    # ---- imports
    def _index_imports(self):
        for sf in self.files.values():
            if sf.lang == "python":
                self._py_imports(sf)
            elif sf.lang in ("javascript", "typescript", "tsx"):
                self._js_imports(sf)

    def _js_imports(self, sf):
        root = sf.tree.root_node
        for n in walk(root):
            if n.type == "import_statement":
                src = n.child_by_field_name("source")
                if src is None:
                    continue
                spec = sf.node_text(src).strip("'\"`")
                names = []
                for c in walk(n):
                    if c.type in ("identifier",) and c.parent.type in ("import_clause", "import_specifier", "namespace_import"):
                        names.append(sf.node_text(c))
                    elif c.type == "import_specifier":
                        alias = c.child_by_field_name("alias") or c.child_by_field_name("name")
                        if alias is not None:
                            names.append(sf.node_text(alias))
                sf.imports.append((spec, sf.line(n), sorted(set(names))))
                for nm in names:
                    sf.bindings[nm] = spec
            elif n.type == "call_expression":
                fn = n.child_by_field_name("function")
                args = n.child_by_field_name("arguments")
                if fn is not None and sf.node_text(fn) == "require" and args is not None and args.named_child_count >= 1:
                    a0 = args.named_children[0]
                    if a0.type in ("string", "template_string"):
                        spec = sf.node_text(a0).strip("'\"`")
                        names = []
                        p = n.parent
                        # const x = require('y'); const {a,b} = require('y'); const x = require('y').z
                        while p is not None and p.type in ("member_expression", "call_expression"):
                            p = p.parent
                        if p is not None and p.type == "variable_declarator":
                            nm = p.child_by_field_name("name")
                            if nm is not None:
                                if nm.type == "identifier":
                                    names.append(sf.node_text(nm))
                                else:
                                    for c in walk(nm):
                                        if c.type in ("shorthand_property_identifier_pattern", "identifier"):
                                            names.append(sf.node_text(c))
                        sf.imports.append((spec, sf.line(n), sorted(set(names))))
                        for nm in names:
                            sf.bindings[nm] = spec

    def _py_imports(self, sf):
        root = sf.tree.root_node
        for n in walk(root):
            if n.type == "import_statement":
                for c in n.named_children:
                    if c.type == "dotted_name":
                        spec = sf.node_text(c); sf.imports.append((spec, sf.line(n), [spec.split(".")[0]])); sf.bindings[spec.split(".")[0]] = spec
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
                        names.append(sf.node_text(c))
                    elif c.type == "aliased_import":
                        al = c.child_by_field_name("alias") or c.child_by_field_name("name"); names.append(sf.node_text(al))
                sf.imports.append((spec, sf.line(n), names))
                for nm in names:
                    sf.bindings[nm] = spec + ":" + nm

    # ---- resolution
    def resolve(self, sf, spec):
        """Resolve an import spec to a repo-relative file path, or None for packages."""
        if sf.lang == "python":
            return self._resolve_py(sf, spec)
        if sf.lang in ("go", "java", "c_sharp"):
            return None
        if not spec.startswith("."):
            # tsconfig-style aliases are not resolved in the prototype
            return None
        base = os.path.normpath(os.path.join(os.path.dirname(sf.path), spec))
        cands = [base] + [base + e for e in (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs")] + [os.path.join(base, "index" + e) for e in (".ts", ".tsx", ".js", ".jsx")]
        for c in cands:
            if c in self.files:
                return c
        return None

    def _resolve_py(self, sf, spec):
        spec = spec.split(":")[0]
        if spec.startswith("."):
            dots = len(spec) - len(spec.lstrip("."))
            rest = spec.lstrip(".")
            d = os.path.dirname(sf.path)
            for _ in range(dots - 1):
                d = os.path.dirname(d)
            base = os.path.normpath(os.path.join(d, *rest.split("."))) if rest else d
        else:
            parts = spec.split(".")
            roots = ["", os.path.dirname(sf.path), "src", "app"]
            top = sf.path.split("/")[0] if "/" in sf.path else ""
            if top: roots.append(top)
            base = None
            for r in roots:
                cand = os.path.normpath(os.path.join(r, *parts))
                if cand + ".py" in self.files or os.path.join(cand, "__init__.py") in self.files:
                    base = cand; break
            if base is None:
                return None
        for c in (base + ".py", os.path.join(base, "__init__.py")):
            if c in self.files:
                return c
        return None

    def service_dir_of(self, rel):
        return rel.split("/")[0] if "/" in rel else "."
