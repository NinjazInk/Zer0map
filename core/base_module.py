"""Abstract base class every Zer0map module inherits from."""
from __future__ import annotations

import threading
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

TRUE_VALUES = {"true", "yes", "y", "1", "on"}
FALSE_VALUES = {"false", "no", "n", "0", "off"}


class OptionError(ValueError):
    """Raised when an option value is invalid."""


class BaseModule(ABC):
    #: Module name used with `use <name>`
    name: str = ""
    #: One-line description shown in `modules`
    description: str = ""

    def __init__(self) -> None:
        # name -> {name, value, default, required, description, type, choices}
        self.options: dict[str, dict[str, Any]] = {}
        # Structured output of the last run (JSON-serializable), used by `export`
        self.results: dict | None = None
        # Set when the user hits Ctrl+C; long-running workers should check `self.cancelled`
        self.stop_event = threading.Event()
        # Back-reference to the shell, set when the module is loaded; lets a module reach
        # sibling modules' last results (e.g. takeover reusing a subdomains run).
        self.shell: Any = None

    # ------------------------------------------------------------------ options
    def add_option(
        self,
        name: str,
        default: Any = None,
        required: bool = False,
        description: str = "",
        type: str = "str",  # str | int | float | bool | choice | path
        choices: list[str] | None = None,
        minimum: float | None = None,
    ) -> None:
        self.options[name.upper()] = {
            "name": name.upper(),
            "value": default,
            "default": default,
            "required": required,
            "description": description,
            "type": type,
            "choices": choices or [],
            "minimum": minimum,
        }

    def _convert(self, opt: dict, raw: str) -> Any:
        kind = opt["type"]
        raw = raw.strip()
        if kind == "int":
            try:
                value: Any = int(raw)
            except ValueError:
                raise OptionError(f"{opt['name']} must be an integer") from None
        elif kind == "float":
            try:
                value = float(raw)
            except ValueError:
                raise OptionError(f"{opt['name']} must be a number") from None
        elif kind == "bool":
            low = raw.lower()
            if low in TRUE_VALUES:
                return True
            if low in FALSE_VALUES:
                return False
            raise OptionError(f"{opt['name']} must be true or false")
        elif kind == "choice":
            low = raw.lower()
            if low not in opt["choices"]:
                raise OptionError(f"{opt['name']} must be one of: {', '.join(opt['choices'])}")
            return low
        elif kind == "path":
            path = Path(raw).expanduser()
            if not path.is_file():
                raise OptionError(f"File not found: {raw}")
            return str(path)
        else:
            return raw
        if opt["minimum"] is not None and value < opt["minimum"]:
            raise OptionError(f"{opt['name']} must be >= {opt['minimum']}")
        return value

    def set_option(self, name: str, raw: str) -> Any:
        key = name.upper()
        if key not in self.options:
            raise OptionError(f"Unknown option '{name}'. Use 'show options' to list options.")
        value = self._convert(self.options[key], raw)
        self.options[key]["value"] = value
        return value

    def unset_option(self, name: str) -> None:
        key = name.upper()
        if key not in self.options:
            raise OptionError(f"Unknown option '{name}'")
        self.options[key]["value"] = self.options[key]["default"]

    def get(self, name: str) -> Any:
        return self.options[name.upper()]["value"]

    def missing_required(self) -> list[str]:
        return [
            n for n, o in self.options.items() if o["required"] and o["value"] in (None, "")
        ]

    def option_values(self) -> dict[str, Any]:
        return {n: o["value"] for n, o in self.options.items()}

    # ------------------------------------------------------------------ execution
    @property
    def cancelled(self) -> bool:
        return self.stop_event.is_set()

    def execute(self) -> dict | None:
        """Called by the shell. Resets state and runs the module."""
        self.stop_event.clear()
        self.results = None
        self.results = self.run()
        return self.results

    @abstractmethod
    def run(self) -> dict:
        """Main logic. Must print output and return a JSON-serializable results dict."""
