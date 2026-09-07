import argparse
import difflib
from importlib.machinery import ModuleSpec
import importlib.util
import os
import re
import sys
from types import ModuleType

RULE_KEYS = (
    "file", # relative path to openssl source root
    "op", # operation enum: insert_after | insert_before | replace | append_file
    "anchor", # regex located in file
    "payload", # code to insert/substitute
    "payload_file",
    "guard",
    "guard_re",
    "when", # openssl version predicate
    "count",
    "flags"
)

def load_rules(path):
    spec = importlib.util.spec_from_file_location("btls-rules", path)
    mod = importlib.util.module_from_spec(spec) # type: ignore
    spec.loader.exec_module(mod) # type: ignore
    rules = getattr(mod, "RULES", None)
    if rules is None:
        sys.exit("RULES attr is empty")

    base = os.path.dirname(os.path.abspath(path))
    snippets_dir = getattr(mod, "SNIPPETS_DIR", None)
    snippets_dir = (os.path.join(base, snippets_dir) if snippets_dir else base)

    return rules, snippets_dir

def rule_fragments(rule):
    keys = {}
    for k in RULE_KEYS:
        if k in rule:
            keys[k] = rule[k]

    conditions = rule.get("conditions")
    if conditions is None:
        return [keys]

    out = []
    for condition in conditions:
        t = dict(keys)
        t.update(condition)
        out.append(t)

    return out

# Достать код фрагмента из ключа (если небольшой) или из файла иначе.
def get_payload(fragment, snippet_dir):
    if "payload_file" in fragment:
        with open(os.path.join(snippet_dir, fragment["payload_file"]), newline="") as f:
            return f.read()
    return fragment.get("payload", "")

# Если во фрагменте не указано по чему определять, что изменения уже применены.
def default_guard(code: str):
    for line in code.splitlines():
        line = line.strip()
        if line:
            return line
    return ""

# Определяем версию openssl.
def openssl_version(root):
    version_dat = os.path.join(root, "VERSION.dat")
    if os.path.exists(version_dat):
        values = {}
        with open(version_dat) as f:
            for line in f:
                key, sep, value = line.partition("=")
                if sep:
                    values[key.strip()] = value.strip()
        try:
            return (int(values["MAJOR"]), int(values["MINOR"]), int(values["PATCH"]))
        except (KeyError, ValueError):
            pass

    legacy = os.path.join(root, "include", "openssl", "opensslv.h")
    if os.path.exists(legacy):
        with open(legacy) as f:
            m = re.search(r"OPENSSL_VERSION_NUMBER\s+0x([0-9a-fA-F]+)", f.read())
        if m:
            num = int(m.group(1), 16)
            return ((num >> 28) & 0xf, (num >> 20) & 0xff, (num >> 12) & 0xff)
    return None

def cmp_openssl_versions(lhs, rhs):
    width = max(len(lhs), len(rhs))
    lhs = tuple(lhs) + (0,) * (width - len(lhs))
    rhs = tuple(rhs) + (0,) * (width - len(rhs))
    return (lhs > rhs) - (lhs < rhs)

CONDITION_CONSTRAINT = re.compile(r"^(>=|<=|==|!=|>|<)\s*([0-9]+(?:\.[0-9]+)*)$")

# Проверяем что версия удовлетворяет условию на версии.
def check_openssl_version(condition, version):
    if not condition:
        return True
    for p in condition.split(","):
        m = CONDITION_CONSTRAINT.match(p.strip())
        if not m:
            raise ValueError("incorrect version predicate: %r" % p)
        op, rhs = m.group(1), tuple(int(x) for x in m.group(2).split("."))
        res = cmp_openssl_versions(version, rhs)
        ok = {">=": res >= 0, "<=": res <= 0, "==": res == 0,
              "!=": res != 0, ">": res > 0, "<": res < 0}[op]
        if not ok:
            return False
    return True

def print_openssl_version(version):
    return "unknown" if version is None else ".".join(str(x) for x in version)


def swap(m):
    if m.group(1) == "$":
        return "$"
    return "\\g<%s>" % (m.group(2) or m.group(3))

DOLLAR = re.compile(r"\$(\$|\{(\d+)\}|(\d+))")

def to_valid_re_payload(payload):
    escaped = payload.replace("\\", "\\\\")
    return DOLLAR.sub(swap, escaped)


DEFAULT_RE_FLAGS = re.MULTILINE | re.DOTALL

def check_guard(fragment, payload, code):
    if 'guard_re' in fragment:
        return re.search(fragment["guard_re"], code, DEFAULT_RE_FLAGS) is not None
    guard = fragment.get("guard") or default_guard(payload)
    return bool(guard) and guard in code

def apply_fragment(fragment, code, payload):
    op = fragment["op"]
    if op not in ("insert_after", "insert_before", "append_file", "replace"):
        return code, "error:unknown-op:%s" % op

    if op == "append_file":
        return code + payload, "applied"

    re_flags = fragment.get("re_flags", DEFAULT_RE_FLAGS)
    count = fragment.get("count", 1)
    try:
        p = re.compile(fragment["anchor"], re_flags)
    except re.error as e:
        return code, "error:bad-anchor:%s" % e

    matches = list(p.finditer(code))
    if not matches:
        return code, "error:anchor-nopt-found"

    if op == "replace":
        new_code, n = p.subn(to_valid_re_payload(payload), code, count)
        return new_code, ("applied" if n else "error:anchor-not-found")

    out, last = [], 0
    for m in matches[:count]:
        pos = m.end() if op == "insert_after" else m.start()
        out.append(code[last:pos])
        out.append(payload)
        last = pos
    out.append(code[last:])
    return "".join(out), "applied"

class FragmentsApplier:
    def __init__(self, root):
        self.root = root
        self.origin = {}
        self.code = {}

    def get(self, file_path):
        if file_path in self.code:
            return self.code[file_path]
        path = os.path.join(self.root, file_path)
        if not os.path.isfile(path):
            return None
        with open(path, encoding="utf-8", errors="surrogateescape", newline="") as f:
            data = f.read()
        self.origin[file_path] = data
        self.code[file_path] = data
        return data

    def set(self, file_path, data):
        self.code[file_path] = data

    def changed(self):
        return [file_path for file_path in sorted(self.code)
                if self.code[file_path] != self.origin[file_path]]

def apply_rule(rule, applier, version, snippet_dir, only_check):
    missed = []
    if_fragments_exist = False
    last_error = None
    for fragment in rule_fragments(rule):
        if not check_openssl_version(fragment.get("when"), version):
            continue
        if_fragments_exist = True
        file_path = fragment["file"]
        code = applier.get(file_path)
        if code is None:
            missed.append(file_path)
            continue
        payload = get_payload(fragment, snippet_dir)
        if check_guard(fragment, payload, code):
            return "skipped", file_path
        if only_check:
            last_error, missed = "error:not-applied", []
            continue
        new_code, status = apply_fragment(fragment, code, payload)
        if status == "applied":
            applier.set(file_path, new_code)
            return "applied", file_path
        last_error = status
    if not if_fragments_exist:
        return "n/e", "no fragment for openssl %s" % print_openssl_version(version)
    if missed:
        return "error:missed-file", ", ".join(missed)
    return last_error or "error:anchor-not-found", ""


def construct_diff(path, before, after):
    return "".join(difflib.unified_diff(
        before.splitlines(keepends=True), after.splitlines(keepends=True),
        fromfile="a/" + path, tofile="b/" + path))

BACK_SUFFIX = ".btls.orig"

def revert(rules, root):
    seen, restored = set(), 0
    for rule in rules:
        for fragment in rule_fragments(rule):
            file_path = fragment.get("file")
            if file_path is None or file_path in seen:
                continue
            seen.add(file_path)
            tgt = os.path.join(root, file_path)
            bak = tgt + BACK_SUFFIX
            if os.path.exists(bak):
                with open(bak, encoding="utf-8", errors="surrogateescape",
                          newline="") as f:
                    data = f.read()
                with open(tgt, "w", encoding="utf-8", errors="surrogateescape",
                          newline="") as f:
                    f.write(data)
                os.remove(bak)
                restored += 1
    print("reverted %d file(s)" % restored)
    return 0

def main():
    ap = argparse.ArgumentParser(description="BTLS OpenSSL patcher")
    ap.add_argument("--root", help="openssl source root")
    ap.add_argument("--rules", required=True, help="rules mod (.py)")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--dry-run", action="store_true", help="show diffs only")
    g.add_argument("--apply", action="store_true", help="write changes")
    g.add_argument("--check", action="store_true", help="report applied state")
    g.add_argument("--revert", action="store_true", help="restore from backups")
    args = ap.parse_args()

    rules, snippets_dir = load_rules(args.rules)
    if args.revert:
        return revert(rules, args.root)

    version = openssl_version(args.root)
    if version is None:
        print("ERROR    cannot detect the OpenSSL version of %s" % args.root,
              file=sys.stderr)
        return 1
    print("# openssl %s in %s" % (print_openssl_version(version), args.root))

    applier, ret = FragmentsApplier(args.root), 0
    counts = {}
    for rule in rules:
        status, detail = apply_rule(rule, applier, version, snippets_dir, args.check)
        tag = status.split(":")[0]
        counts[tag] = counts.get(tag, 0) + 1
        print("%-8s %-34s %s" % (tag.upper(), rule["id"], detail))
        if tag == "error":
            print("        - %s" % status, file=sys.stderr)
            ret = 1

    if args.check:
        ret = 1 if counts.get("error") or counts.get("applied") else ret
    elif args.dry_run:
        for file_path in applier.changed():
            sys.stdout.write(construct_diff(file_path, applier.origin[file_path], applier.code[file_path]))
    elif args.apply:
        for file_path in applier.changed():
            dst = os.path.join(args.root, file_path)
            # back = dst + BACK_SUFFIX
            # if not os.path.exists(back):
            #     with open(back, "w", encoding="utf-8", errors="surrogateescape",
            #               newline="") as f:
            #         f.write(applier.origin[file_path])
            with open(dst, "w", encoding="utf-8", errors="surrogateescape",
                      newline="") as f:
                f.write(applier.code[file_path])

    print("# %s" % ", ".join("%s=%d" % (k, v) for k, v in sorted(counts.items())))
    return ret

if __name__ == "__main__":
    sys.exit(main())
