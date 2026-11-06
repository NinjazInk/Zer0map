"""Interactive Metasploit-style shell: prompt, command dispatch and tab-completion."""
from __future__ import annotations

import importlib
import inspect
import pkgutil
import sys
import time
from pathlib import Path
from typing import Callable, Iterable

from prompt_toolkit import PromptSession
from prompt_toolkit.completion import Completer, Completion, PathCompleter
from prompt_toolkit.document import Document
from prompt_toolkit.formatted_text import FormattedText
from prompt_toolkit.history import FileHistory, InMemoryHistory
from prompt_toolkit.styles import Style
from rich.text import Text

import modules as modules_pkg
from core.base_module import BaseModule, OptionError
from core.output import (
    add_row,
    console,
    export_results,
    make_table,
    print_error,
    print_good,
    print_info,
    print_warn,
    utc_now,
)
from core.utils import VERSION, ReconError

BANNER_ART = r"""
 _____             ____
/__  /  ___  _____/ __ \____ ___  ____ _____
  / /  / _ \/ ___/ / / / __ `__ \/ __ `/ __ \
 / /__/  __/ /  / /_/ / / / / / / /_/ / /_/ /
/____/\___/_/   \____/_/ /_/ /_/\__,_/ .___/
                                    /_/
"""

DISCLAIMER = ("For authorized testing and educational purposes only. "
              "Always obtain permission before scanning targets you do not own.")

COMMANDS: dict[str, str] = {
    "help": "Show this help (also: ?)",
    "modules": "List available modules (also: show modules)",
    "use": "Load a module: use <module>",
    "back": "Unload the current module",
    "show": "show options | show modules | show info",
    "info": "Show details about the current module",
    "set": "Set a module option: set <OPTION> <value>",
    "unset": "Reset an option to its default: unset <OPTION>",
    "run": "Run the current module (also: exploit)",
    "export": "Save the last results: export <file.json|file.md>",
    "banner": "Redisplay the startup banner",
    "clear": "Clear the screen",
    "exit": "Exit Zer0map (also: quit)",
}
ALIASES = {"?": "help", "exploit": "run", "quit": "exit", "options": "show options"}

PROMPT_STYLE = Style.from_dict({
    "prompt": "bold",
    "module": "ansired bold",
    "arrow": "",
})


def discover_modules() -> dict[str, type[BaseModule]]:
    """Import every module in the modules/ package and register BaseModule subclasses."""
    registry: dict[str, type[BaseModule]] = {}
    for info in pkgutil.iter_modules(modules_pkg.__path__):
        try:
            mod = importlib.import_module(f"modules.{info.name}")
        except Exception as exc:  # a broken module must not take down the shell
            print_error(f"Failed to load module '{info.name}': {exc}")
            continue
        for _, obj in inspect.getmembers(mod, inspect.isclass):
            if issubclass(obj, BaseModule) and obj is not BaseModule and obj.__module__ == mod.__name__ and obj.name:
                registry[obj.name] = obj
    return dict(sorted(registry.items()))


class ShellCompleter(Completer):
    def __init__(self, shell: "Zer0mapShell") -> None:
        self.shell = shell
        self.path_completer = PathCompleter(expanduser=True)

    @staticmethod
    def _matches(word: str, candidates: Iterable[str], meta: Callable[[str], str] | None = None,
                 suffix: str = " "):
        low = word.lower()
        for c in candidates:
            if c.lower().startswith(low):
                yield Completion(c + suffix, start_position=-len(word), display=c,
                                 display_meta=meta(c) if meta else None)

    def get_completions(self, document: Document, complete_event):
        text = document.text_before_cursor
        parts = text.split()
        if not parts or (len(parts) == 1 and not text.endswith(" ")):
            word = parts[0] if parts else ""
            names = list(COMMANDS) + ["exploit", "quit", "options"]
            yield from self._matches(word, sorted(set(names)), lambda c: COMMANDS.get(c, ""))
            return
        cmd = parts[0].lower()
        if text.endswith(" "):
            parts.append("")
        word, index = parts[-1], len(parts) - 1
        mod = self.shell.current
        if cmd == "use" and index == 1:
            yield from self._matches(word, self.shell.registry, lambda n: self.shell.registry[n].description)
        elif cmd == "show" and index == 1:
            yield from self._matches(word, ["options", "modules", "info"])
        elif cmd in ("set", "unset") and index == 1 and mod:
            yield from self._matches(word, mod.options, lambda n: mod.options[n]["description"])
        elif cmd == "set" and index == 2 and mod:
            opt = mod.options.get(parts[1].upper())
            if opt and opt["type"] == "bool":
                yield from self._matches(word, ["true", "false"])
            elif opt and opt["type"] == "choice":
                yield from self._matches(word, opt["choices"])
            elif opt and opt["type"] == "path":
                yield from self.path_completer.get_completions(Document(word), complete_event)
            elif opt and opt["name"] == "PORTS":
                yield from self._matches(word, ["top100", "top1000", "all", "1-1024"])
        elif cmd == "export" and index == 1:
            yield from self.path_completer.get_completions(Document(word), complete_event)


class Zer0mapShell:
    def __init__(self) -> None:
        self.registry = discover_modules()
        self.instances: dict[str, BaseModule] = {}
        self.current: BaseModule | None = None
        self.last_result: dict | None = None
        self.session: PromptSession | None = None
        self.handlers: dict[str, Callable[[list[str], str], bool | None]] = {
            "help": self.do_help, "modules": self.do_modules, "use": self.do_use,
            "back": self.do_back, "show": self.do_show, "info": self.do_info, "set": self.do_set,
            "unset": self.do_unset, "run": self.do_run, "export": self.do_export,
            "banner": self.do_banner, "clear": self.do_clear, "exit": self.do_exit,
        }

    # ------------------------------------------------------------------ prompt
    def prompt_tokens(self) -> FormattedText:
        tokens = [("class:prompt", "recon")]
        if self.current:
            tokens += [("", " ("), ("class:module", self.current.name), ("", ")")]
        tokens.append(("class:arrow", " > "))
        return FormattedText(tokens)

    def prompt_plain(self) -> str:
        return "".join(t[1] for t in self.prompt_tokens())

    def _make_session(self) -> PromptSession:
        try:
            history = FileHistory(str(Path.home() / ".zer0map_history"))
        except OSError:
            history = InMemoryHistory()
        return PromptSession(history=history, completer=ShellCompleter(self),
                             complete_while_typing=False, style=PROMPT_STYLE)

    def loop(self) -> None:
        interactive = sys.stdin.isatty() and sys.stdout.isatty()
        if interactive:
            self.session = self._make_session()
        while True:
            try:
                if interactive:
                    line = self.session.prompt(self.prompt_tokens)
                else:
                    line = input()
                    console.print(Text(self.prompt_plain(), style="bold"), Text(line), sep="")
            except KeyboardInterrupt:
                # Ctrl+C at the prompt clears the line; it never exits the shell
                continue
            except EOFError:
                console.print()
                self.do_exit([], "")
                return
            if self.onecmd(line) is False:
                return

    # ------------------------------------------------------------------ dispatch
    def onecmd(self, line: str) -> bool:
        line = line.strip()
        if not line or line.startswith("#"):
            return True
        head, _, rest = line.partition(" ")
        head = head.lower()
        if head in ALIASES:
            expanded = ALIASES[head]
            head, _, extra = expanded.partition(" ")
            rest = (extra + " " + rest).strip()
        if head == "show" and rest.lower().strip() == "modules":
            head, rest = "modules", ""
        handler = self.handlers.get(head)
        if not handler:
            if head in self.registry:
                print_error(f"Unknown command '{head}'. Did you mean 'use {head}'?")
            else:
                print_error(f"Unknown command '{head}'. Type 'help' for a list of commands.")
            return True
        try:
            return handler(rest.split(), rest) is not False
        except KeyboardInterrupt:
            print_warn("Interrupted")
        except Exception as exc:  # last-resort safety net: never crash the shell
            print_error(f"Unexpected error: {type(exc).__name__}: {exc}")
        return True

    # ------------------------------------------------------------------ commands
    def banner(self) -> None:
        console.print(Text(BANNER_ART, style="critical"), end="")
        lines = [
            f"[ Zer0map v{VERSION} ]",
            f"[ {len(self.registry)} modules | Recon Framework ]",
            "[ Type 'help' to get started ]",
        ]
        width = 56
        console.print(Text(lines[0].center(width), style="heading"))
        console.print(Text(lines[1].center(width), style="info"))
        console.print(Text(lines[2].center(width), style="muted"))
        console.print()
        console.print(Text(f"[!] {DISCLAIMER}", style="warning"))
        console.print()

    def do_banner(self, args, raw):
        self.banner()

    def do_help(self, args, raw):
        table = make_table("Global Commands", ["Command", "Description"])
        for name, desc in COMMANDS.items():
            add_row(table, Text(name, style="option"), desc)
        console.print(table)
        self.do_modules([], "")
        console.print(Text("Example:  use headers  ->  set URL https://example.com  ->  run  ->  export report.md",
                           style="muted"))

    def do_modules(self, args, raw):
        table = make_table("Modules", ["Name", "Description"])
        for name, cls in self.registry.items():
            add_row(table, Text(name, style="option"), cls.description)
        console.print(table)

    def do_use(self, args, raw):
        if not args:
            print_error("Usage: use <module>  (see 'modules')")
            return
        name = args[0].lower()
        if name not in self.registry:
            print_error(f"No such module '{name}'. Available: {', '.join(self.registry)}")
            return
        if name not in self.instances:  # keep one instance so options persist between uses
            self.instances[name] = self.registry[name]()
        self.current = self.instances[name]
        print_info(f"Loaded module {name}: {self.current.description}")

    def do_back(self, args, raw):
        self.current = None

    def _require_module(self) -> BaseModule | None:
        if not self.current:
            print_error("No module loaded. Use 'use <module>' first (see 'modules').")
        return self.current

    def do_show(self, args, raw):
        what = args[0].lower() if args else ""
        if what == "modules":
            self.do_modules([], "")
        elif what == "options":
            self.show_options()
        elif what == "info":
            self.do_info([], "")
        else:
            print_error("Usage: show options | show modules | show info")

    def show_options(self) -> None:
        mod = self._require_module()
        if not mod:
            return
        table = make_table(f"Module options ({mod.name})",
                           ["Name", "Current Value", "Required", "Description"])
        for opt in mod.options.values():
            value = opt["value"]
            if isinstance(value, bool):
                value = str(value).lower()
            missing = opt["required"] and value in (None, "")
            add_row(
                table,
                Text(opt["name"], style="option"),
                Text("" if value is None else str(value), style="" if not missing else "critical"),
                Text("yes", style="warning") if opt["required"] else Text("no", style="muted"),
                opt["description"],
            )
        console.print(table)

    def do_info(self, args, raw):
        mod = self._require_module()
        if not mod:
            return
        console.print(Text(f"\n  Module: {mod.name}", style="heading"))
        console.print(Text(f"  {mod.description}\n"))
        doc = (sys.modules[type(mod).__module__].__doc__ or "").strip()
        if doc:
            console.print(Text(f"  {doc}\n", style="muted"))
        self.show_options()

    def do_set(self, args, raw):
        mod = self._require_module()
        if not mod:
            return
        name, _, value = raw.strip().partition(" ")
        value = value.strip()
        if not name or not value:
            print_error("Usage: set <OPTION> <value>")
            return
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
            value = value[1:-1]
        try:
            result = mod.set_option(name, value)
        except OptionError as exc:
            print_error(str(exc))
            return
        shown = str(result).lower() if isinstance(result, bool) else result
        console.print(Text.assemble((name.upper(), "option"), " => ", str(shown)))

    def do_unset(self, args, raw):
        mod = self._require_module()
        if not mod:
            return
        if not args:
            print_error("Usage: unset <OPTION>")
            return
        try:
            mod.unset_option(args[0])
            print_info(f"{args[0].upper()} reset to default")
        except OptionError as exc:
            print_error(str(exc))

    def do_run(self, args, raw):
        mod = self._require_module()
        if not mod:
            return
        missing = mod.missing_required()
        if missing:
            print_error(f"Missing required option(s): {', '.join(missing)}")
            for m in missing:
                console.print(Text.assemble("    ", (m, "option"), f"  {mod.options[m]['description']}"))
            return
        print_info(f"Running {mod.name}... (Ctrl+C to cancel)")
        start = time.monotonic()
        try:
            results = mod.execute()
        except KeyboardInterrupt:
            mod.stop_event.set()
            console.print()
            print_warn("Operation cancelled by user")
            return
        except (ReconError, OptionError) as exc:
            print_error(str(exc))
            return
        except Exception as exc:
            print_error(f"Module {mod.name} failed: {type(exc).__name__}: {exc}")
            return
        elapsed = time.monotonic() - start
        if results is not None:
            self.last_result = {
                "tool": "Zer0map",
                "version": VERSION,
                "module": mod.name,
                "timestamp": utc_now(),
                "duration_seconds": round(elapsed, 2),
                "options": mod.option_values(),
                "results": results,
            }
        console.print()
        print_good(f"Module {mod.name} finished in {elapsed:.1f}s. Use 'export <file.json|file.md>' to save results.")

    def do_export(self, args, raw):
        filename = raw.strip().strip("'\"")
        if not filename:
            print_error("Usage: export <filename.json|filename.md>")
            return
        if not self.last_result:
            print_error("Nothing to export yet. Run a module first.")
            return
        try:
            path = export_results(self.last_result, filename)
        except ValueError as exc:
            print_error(str(exc))
            return
        except OSError as exc:
            print_error(f"Could not write {filename}: {exc.strerror or exc}")
            return
        print_good(f"Exported {self.last_result['module']} results to {path}")

    def do_clear(self, args, raw):
        console.clear()

    def do_exit(self, args, raw):
        print_info("Goodbye. Happy (authorized) hunting.")
        return False
