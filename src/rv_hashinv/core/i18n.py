"""Report wording in English, Spanish and French (resources/i18n/*.json, shared with the Rust profile)."""

from __future__ import annotations

import json
from functools import cache
from importlib import resources

LANGS = ("en", "es", "fr")


@cache
def catalog(lang: str) -> dict:
    lang = lang if lang in LANGS else "en"
    return json.loads(resources.files("rv_hashinv.resources").joinpath(f"i18n/{lang}.json").read_text(encoding="utf-8"))


def parse_langs(value: str) -> list[str]:
    out: list[str] = []
    for part in (p.strip().lower() for p in value.split(",")):
        if not part:
            continue
        if part == "all":
            return list(LANGS)
        if part not in LANGS:
            raise ValueError(f"unsupported language '{part}': use en, es, fr or all")
        if part not in out:
            out.append(part)
    if not out:
        raise ValueError("no language given: use en, es, fr or all")
    return out


def fill(template: str, params: dict[str, str]) -> str:
    for k, v in params.items():
        template = template.replace("%{" + k + "}", v)
    return template


def label(lang: str, key: str) -> str:
    return catalog(lang)["labels"].get(key, key)


def severity(lang: str, key: str) -> str:
    return catalog(lang)["severity"].get(key, key)


def finding(lang: str, code: str, params: dict[str, str]) -> tuple[str, str, str]:
    f = catalog(lang)["findings"].get(code, {})
    return tuple(fill(f.get(k, code), params) for k in ("title", "shows", "does_not_prove"))  # type: ignore[return-value]


def limitation(lang: str, code: str) -> str:
    return catalog(lang)["limitations"].get(code, code)
