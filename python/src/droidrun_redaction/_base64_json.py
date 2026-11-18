"""The base64 JSON check of the full tier (SPEC 5.7): the 1Password token body is base64 whose bytes, read as
Latin-1 text, are one JSON object or array.

Own decoder and own JSON syntax check, so every language gives the same answer (no library dialects: `NaN`,
trailing garbage, depth limits). The check is iterative.
"""

_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
_SEXTET = {char: index for index, char in enumerate(_ALPHABET)}
_GROUP = 4
_PAD = "="

_TAB, _LINE_FEED, _CARRIAGE_RETURN, _SPACE = 0x09, 0x0A, 0x0D, 0x20
_QUOTE, _BACKSLASH = 0x22, 0x5C
_WHITESPACE = frozenset((_SPACE, _TAB, _LINE_FEED, _CARRIAGE_RETURN))
_DIGITS = frozenset(range(0x30, 0x3A))
_HEX = _DIGITS | frozenset(range(0x41, 0x47)) | frozenset(range(0x61, 0x67))
_ESCAPES = frozenset(b'"\\/bfnrt')
_LITERALS = (b"true", b"false", b"null")
_OPEN_OBJECT, _CLOSE_OBJECT, _OPEN_ARRAY, _CLOSE_ARRAY = 0x7B, 0x7D, 0x5B, 0x5D
_COMMA, _COLON, _MINUS = 0x2C, 0x3A, 0x2D
_NONE = -1


def decode_base64(data: str) -> bytes | None:
    """Forgiving base64 decode (WHATWG): up to two trailing `=` only when the length is a multiple of 4."""
    if len(data) % _GROUP == 0:
        data = data.removesuffix(_PAD * 2) if data.endswith(_PAD * 2) else data.removesuffix(_PAD)
    if len(data) % _GROUP == 1:
        return None
    out = bytearray()
    buffer = 0
    bits = 0
    for char in data:
        sextet = _SEXTET.get(char)
        if sextet is None:
            return None
        buffer = (buffer << 6) | sextet
        bits += 6
        if bits >= 8:
            bits -= 8
            out.append((buffer >> bits) & 0xFF)
            buffer &= (1 << bits) - 1
    return bytes(out)


class _Scanner:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.position = 0

    def peek(self) -> int:
        return self.data[self.position] if self.position < len(self.data) else _NONE

    def skip_whitespace(self) -> None:
        while self.peek() in _WHITESPACE:
            self.position += 1

    def string(self) -> bool:
        self.position += 1
        while True:
            byte = self.peek()
            self.position += 1
            if byte == _NONE or byte < _SPACE:
                return False
            if byte == _QUOTE:
                return True
            if byte != _BACKSLASH:
                continue
            escape = self.peek()
            self.position += 1
            if escape == 0x75:
                for _ in range(_GROUP):
                    if self.peek() not in _HEX:
                        return False
                    self.position += 1
            elif escape not in _ESCAPES:
                return False

    def digits(self) -> bool:
        if self.peek() not in _DIGITS:
            return False
        while self.peek() in _DIGITS:
            self.position += 1
        return True

    def number(self) -> bool:
        if self.peek() == _MINUS:
            self.position += 1
        if self.peek() == 0x30:
            self.position += 1
        elif not self.digits():
            return False
        if self.peek() == 0x2E:
            self.position += 1
            if not self.digits():
                return False
        if self.peek() in (0x65, 0x45):
            self.position += 1
            if self.peek() in (0x2B, _MINUS):
                self.position += 1
            if not self.digits():
                return False
        return True

    def literal(self) -> bool:
        for word in _LITERALS:
            if self.data.startswith(word, self.position):
                self.position += len(word)
                return True
        return False

    def object_key(self) -> bool:
        """`"key"` and `:`, the start of an object member."""
        self.skip_whitespace()
        if self.peek() != _QUOTE or not self.string():
            return False
        self.skip_whitespace()
        if self.peek() != _COLON:
            return False
        self.position += 1
        return True

    def scalar(self) -> bool:
        byte = self.peek()
        if byte == _QUOTE:
            return self.string()
        if byte == _MINUS or byte in _DIGITS:
            return self.number()
        return self.literal()

    def open_container(self, stack: list[bool], opening: int) -> str:
        """After an opening bracket: an empty container closes at once, else the first member starts."""
        is_object = opening == _OPEN_OBJECT
        self.position += 1
        stack.append(is_object)
        self.skip_whitespace()
        if self.peek() == (_CLOSE_OBJECT if is_object else _CLOSE_ARRAY):
            self.position += 1
            stack.pop()
            return "closed"
        if is_object and not self.object_key():
            return "bad"
        return "value"

    def after_value(self, stack: list[bool]) -> str:
        """After a value: `,` and the next member, or the closing bracket of the innermost container."""
        in_object = stack[-1]
        byte = self.peek()
        if byte == _COMMA:
            self.position += 1
            return "bad" if in_object and not self.object_key() else "value"
        if byte != (_CLOSE_OBJECT if in_object else _CLOSE_ARRAY):
            return "bad"
        self.position += 1
        stack.pop()
        return "closed"


def is_json_container(data: bytes) -> bool:
    """True when `data` is one JSON text (ECMA-404) whose top value is an object or array."""
    scanner = _Scanner(data)
    scanner.skip_whitespace()
    if scanner.peek() not in (_OPEN_OBJECT, _OPEN_ARRAY):
        return False
    stack: list[bool] = []
    expect_value = True
    while expect_value or stack:
        scanner.skip_whitespace()
        byte = scanner.peek()
        if not expect_value:
            step = scanner.after_value(stack)
        elif byte in (_OPEN_OBJECT, _OPEN_ARRAY):
            step = scanner.open_container(stack, byte)
        else:
            step = "closed" if scanner.scalar() else "bad"
        if step == "bad":
            return False
        expect_value = step == "value"
    scanner.skip_whitespace()
    return scanner.peek() == _NONE


def is_base64_json(token: str) -> bool:
    """True when `token` decodes as base64 to bytes that, read as Latin-1, are a JSON object or array."""
    data = decode_base64(token)
    return data is not None and is_json_container(data)
