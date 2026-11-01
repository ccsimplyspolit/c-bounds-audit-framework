from __future__ import annotations

import re
from typing import List

from .models import Token

TOKEN_SPECIFICATION = [
    ("COMMENT_MULTI", r"/\*[\s\S]*?\*/"),
    ("COMMENT_SINGLE", r"//[^\n]*"),
    ("PREPROCESSOR", r"#[^\n]*"),
    ("STRING", r'"(?:\\.|[^"\\])*"'),
    ("CHAR", r"'(?:\\.|[^'\\])*'"),
    ("FLOAT", r"\b\d+\.\d+(?:[eE][+-]?\d+)?[fFlL]?\b"),
    ("HEX", r"\b0[xX][0-9a-fA-F]+[uUlL]*\b"),
    ("OCTAL", r"\b0[0-7]+[uUlL]*\b"),
    ("INTEGER", r"\b\d+[uUlL]*\b"),
    ("ARROW", r"->"),
    ("INCREMENT", r"\+\+"),
    ("DECREMENT", r"--"),
    ("LE_OP", r"<="),
    ("GE_OP", r">="),
    ("EQ_OP", r"=="),
    ("NE_OP", r"!="),
    ("AND_OP", r"&&"),
    ("OR_OP", r"\|\|"),
    ("ADD_ASSIGN", r"\+="),
    ("SUB_ASSIGN", r"-="),
    ("MUL_ASSIGN", r"\*="),
    ("DIV_ASSIGN", r"/="),
    ("MOD_ASSIGN", r"%="),
    ("IDENTIFIER", r"\b[a-zA-Z_][a-zA-Z0-9_]*\b"),
    ("PUNCTUATOR", r"[;{},:=()\[\]<>+*\-/&|^!~?]"),
    ("NEWLINE", r"\n"),
    ("SKIP", r"[ \t\r]+"),
    ("MISMATCH", r"."),
]

TOKEN_REGEX = re.compile("|".join(f"(?P<{pair[0]}>{pair[1]})" for pair in TOKEN_SPECIFICATION))


def tokenize(code: str) -> List[Token]:
    """Tokenize C/C++ source code into a clean stream of Token objects."""
    tokens: List[Token] = []
    line_num = 1
    line_start = 0

    for mo in TOKEN_REGEX.finditer(code):
        kind = mo.lastgroup
        value = mo.group()
        col = mo.start() - line_start + 1

        if kind == "NEWLINE":
            line_start = mo.end()
            line_num += 1
            continue
        elif kind == "SKIP":
            continue
        elif kind == "COMMENT_MULTI":
            lines_in_comment = value.count("\n")
            if lines_in_comment > 0:
                line_num += lines_in_comment
                line_start = mo.end() - (len(value) - value.rfind("\n") - 1)
            continue
        elif kind == "COMMENT_SINGLE":
            continue
        elif kind == "PREPROCESSOR":
            tokens.append(Token(type="PREPROCESSOR", value=value, line=line_num, column=col))
        elif kind == "MISMATCH":
            # Unrecognized character, skip or record as token
            continue
        else:
            tokens.append(Token(type=kind, value=value, line=line_num, column=col))

    return tokens
