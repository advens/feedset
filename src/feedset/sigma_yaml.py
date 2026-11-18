"""YAML subset for Sigma rule files. No third-party parser.

The loader accepts the block style those files use: mappings, lists,
quoted and plain scalars, comments, and block scalars. A tab, an
anchor, or an alias is an error. Flow collections are an error.
"""

from __future__ import annotations


class YamlError(ValueError):
    pass


def load_all(text: str) -> list[object]:
    """Parse every document in ``text``. Empty documents are omitted."""
    normalized = text.replace("\r\n", "\n").replace("\r", "\n")
    chunks: list[str] = []
    current: list[str] = []
    for line in normalized.split("\n"):
        if line.strip() in {"---", "..."}:
            chunks.append("\n".join(current))
            current = []
            continue
        current.append(line)
    chunks.append("\n".join(current))
    docs = []
    for chunk in chunks:
        if not chunk.strip():
            continue
        docs.extend(_Parser(chunk).documents())
    return docs


class _Parser:
    def __init__(self, text: str) -> None:
        self.lines = text.split("\n")
        self.i = 0

    def documents(self) -> list[object]:
        value = self._parse_node(0)
        self._skip()
        if self.i < len(self.lines):
            raise YamlError("trailing yaml")
        if value is _MISSING:
            return []
        return [value]

    def _skip(self) -> None:
        while self.i < len(self.lines):
            stripped = self.lines[self.i].lstrip(" ")
            if stripped == "" or stripped.startswith("#"):
                if "\t" in self.lines[self.i]:
                    raise YamlError("tab in yaml")
                self.i += 1
                continue
            return

    def _indent(self, line: str) -> int:
        count = 0
        for char in line:
            if char == " ":
                count += 1
            elif char == "\t":
                raise YamlError("tab in yaml")
            else:
                break
        return count

    def _parse_node(self, indent: int) -> object:
        self._skip()
        if self.i >= len(self.lines):
            return _MISSING
        line = self.lines[self.i]
        current = self._indent(line)
        if current < indent:
            return _MISSING
        stripped = line[current:]
        if stripped.startswith("- ") or stripped == "-":
            return self._parse_list(current)
        return self._parse_map(current)

    def _parse_list(self, indent: int) -> list[object]:
        items: list[object] = []
        while self.i < len(self.lines):
            self._skip()
            if self.i >= len(self.lines):
                break
            line = self.lines[self.i]
            current = self._indent(line)
            if current < indent:
                break
            if current > indent:
                raise YamlError("list indent")
            stripped = line[current:]
            if not (stripped.startswith("- ") or stripped == "-"):
                break
            body = stripped[2:] if stripped.startswith("- ") else ""
            self.i += 1
            items.append(self._list_item(body, indent))
        return items

    def _list_item(self, body: str, indent: int) -> object:
        body = body.strip()
        if body == "":
            nested = self._parse_node(indent + 1)
            return None if nested is _MISSING else nested
        if _is_key(body):
            key, value, explicit = _split_key(body)
            mapping = {key: self._take(value, explicit, indent + 2)}
            mapping.update(self._parse_map(indent + 2))
            return mapping
        if body in {"|", ">", "|-", ">+", "|+", ">-"}:
            return self._block_scalar(body, indent + 1)
        return _scalar(body)

    def _parse_map(self, indent: int) -> dict[str, object]:
        mapping: dict[str, object] = {}
        while self.i < len(self.lines):
            self._skip()
            if self.i >= len(self.lines):
                break
            line = self.lines[self.i]
            current = self._indent(line)
            if current < indent:
                break
            if current > indent:
                raise YamlError("map indent")
            stripped = line[current:]
            if stripped.startswith("- ") or stripped == "-":
                break
            if not _is_key(stripped):
                raise YamlError("map key")
            key, value, explicit = _split_key(stripped)
            self.i += 1
            mapping[key] = self._take(value, explicit, indent + 1)
        return mapping

    def _take(self, value: object, explicit: object, indent: int) -> object:
        if explicit is not _MORE:
            return value
        if isinstance(value, str) and value in _BLOCK:
            return self._block_scalar(value, indent)
        nested = self._parse_node(indent)
        return None if nested is _MISSING else nested

    def _block_scalar(self, marker: str, indent: int) -> str:
        keep = marker.startswith("|")
        rows: list[str] = []
        while self.i < len(self.lines):
            line = self.lines[self.i]
            if line.strip() == "":
                rows.append("")
                self.i += 1
                continue
            current = self._indent(line)
            if current < indent:
                break
            rows.append(line[indent:])
            self.i += 1
        while rows and rows[-1] == "":
            rows.pop()
        joiner = "\n" if keep else " "
        return joiner.join(rows)


class _Missing:
    pass


class _More:
    pass


_MISSING = _Missing()
_MORE = _More()
_BLOCK = {"|", ">", "|-", ">+", "|+", ">-"}


def _is_key(text: str) -> bool:
    if text.startswith(("'", '"', "|", ">")):
        return False
    if text.startswith(("- ", "-")):
        return False
    name, sep, rest = text.partition(":")
    if sep != ":" or not name or name.startswith(("&", "*", "!")):
        return False
    if rest != "" and not rest.startswith((" ", "#")):
        return False
    if any(ch in name for ch in " \t#{}[]"):
        return False
    return True


def _split_key(text: str) -> tuple[str, object, object]:
    name, _, rest = text.partition(":")
    if "&" in name or "*" in name:
        raise YamlError("yaml anchor")
    value = rest.strip()
    if value == "" or value.startswith("#"):
        return name, None, _MORE
    if value in {"|", ">", "|-", ">+", "|+", ">-"}:
        return name, value, _MORE
    if value.startswith(("[", "{")):
        raise YamlError("flow yaml")
    return name, _scalar(value), None


def _scalar(text: str) -> object:
    if text.startswith("'"):
        return _unquote(text, "'")
    if text.startswith('"'):
        return _unquote(text, '"')
    if text.startswith(("&", "*")):
        raise YamlError("yaml anchor")
    if text.startswith(("[", "{")):
        raise YamlError("flow yaml")
    plain = _strip_comment(text).strip()
    if plain in {"", "null", "~", "Null", "NULL"}:
        return None
    return plain


def _strip_comment(text: str) -> str:
    for index in range(len(text)):
        if text[index] == "#" and (index == 0 or text[index - 1] == " "):
            return text[:index]
    return text


def _unquote(text: str, quote: str) -> str:
    body = _strip_comment(text).strip()
    if len(body) < 2 or not body.endswith(quote):
        raise YamlError("open quote")
    inner = body[1:-1]
    if quote == "'":
        return inner.replace("''", "'")
    out = []
    index = 0
    while index < len(inner):
        char = inner[index]
        if char != "\\":
            out.append(char)
            index += 1
            continue
        index += 1
        if index >= len(inner):
            raise YamlError("open quote")
        escaped = inner[index]
        out.append({"n": "\n", "t": "\t", "r": "\r", '"': '"', "\\": "\\"}.get(escaped, escaped))
        index += 1
    return "".join(out)
