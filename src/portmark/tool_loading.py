from __future__ import annotations

import pkgutil

from .tools import ToolRegistry


class ToolLoaderError(ValueError):
    pass


def load_tools(path: str | None) -> ToolRegistry | None:
    if not path:
        return None
    module_name, separator, object_path = path.partition(":")
    if not separator or not module_name or not object_path:
        raise ToolLoaderError("--tools must use module:function syntax")
    try:
        # Every dotted part a plain identifier, so pkgutil.resolve_name (which also accepts forms without
        # a colon) is only ever handed the module:attribute shape checked above.
        if not all(part.isidentifier() for part in (*module_name.split("."), *object_path.split("."))):
            raise ImportError(path)
        loaded = pkgutil.resolve_name(path)
    except (ImportError, AttributeError) as error:
        raise ToolLoaderError(f"could not load --tools {path!r}") from error
    try:
        registry = loaded() if callable(loaded) else loaded
    except Exception as error:
        raise ToolLoaderError("--tools loader failed") from error
    if not isinstance(registry, ToolRegistry):
        raise ToolLoaderError("--tools loader must return a portmark.tools.ToolRegistry")
    return registry
