import argparse
import json
import os
import runpy
import site
import subprocess
import sys
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import NotRequired, TypedDict
from venv import create

import ida_idaapi
import ida_kernwin
import ida_loader
import pkg_resources

PLUGIN_NAME = "IDAVenv"

PYTHON_VERSION = f"python{sys.version_info.major}.{sys.version_info.minor}"

BIN_PATH = {
    "nt": "Scripts",
    "posix": "bin",
}

LIB_PATH = {
    "nt": "Lib/site-packages",
    "posix": f"lib/{PYTHON_VERSION}/site-packages",
}

PYTHON_EXECUTABLE_PATH = {
    "nt": "Scripts/python.exe",
    "posix": "bin/python",
}


def _activate_venv(venv_path: Path) -> None:
    base_path = str(venv_path.resolve())
    venv_dict = {
        "VIRTUAL_ENV": base_path,
        "_OLD_VIRTUAL_PATH": os.environ.pop("PATH", ""),
        "_OLD_SYS_PATH": sys.path,
        "_OLD_PREFIX": sys.prefix,
    }

    try:
        bin_dir = f"{base_path}/{BIN_PATH[os.name]}"
    except KeyError:
        # java/jython
        raise RuntimeError("Jython not supported (yet?)") from None

    # add venv to list
    venvs = json.loads(os.environ.get("IDAVenvs", "[]"))
    venvs.append(venv_dict)
    os.environ["IDAVenvs"] = json.dumps(venvs)

    # save old path
    os.environ["_OLD_VIRTUAL_PATH"] = venv_dict["_OLD_VIRTUAL_PATH"]

    # prepend bin to PATH (this file is inside the bin directory)
    os.environ["PATH"] = os.pathsep.join(
        [bin_dir] + os.environ.get("PATH", "").split(os.pathsep)
    )
    os.environ["VIRTUAL_ENV"] = venv_dict["VIRTUAL_ENV"]

    # add the virtual environments libraries to the host python import mechanism
    prev_length = len(sys.path)

    lib = f"{base_path}/{LIB_PATH[os.name]}"
    path = os.path.realpath(os.path.join(bin_dir, lib))
    site.addsitedir(path)

    sys.path[:] = sys.path[prev_length:] + sys.path[0:prev_length]
    sys.prefix = sys.exec_prefix = base_path


def create_venv(venv_path: Path) -> None:
    with get_context():
        create(venv_path, system_site_packages=True, symlinks=False, with_pip=True)


def activate_venv(venv_path: Path, dependencies: list[str] | None = None) -> None:
    print("[IDAVenv] activate_venv")
    python_path = venv_path / PYTHON_EXECUTABLE_PATH[os.name]
    if not python_path.is_file():
        create_venv(venv_path)

    _activate_venv(venv_path)

    if dependencies:
        install_dependencies(venv_path=venv_path, dependencies=dependencies)


def deactivate_venv() -> None:
    print("[IDAVenv] deactivate_venv")
    venv_dicts = json.loads(os.environ.get("IDAVenvs", "[]"))
    if not venv_dicts:
        return

    venv_dict = venv_dicts.pop()
    if not venv_dict:
        return

    # restore old path
    os.environ["PATH"] = os.environ.pop("_OLD_VIRTUAL_PATH", "")
    sys.path = venv_dict["_OLD_SYS_PATH"]
    # restore prefix
    sys.prefix = sys.exec_prefix = venv_dict["_OLD_PREFIX"]
    os.environ["IDAVenvs"] = json.dumps(venv_dicts)

    # TODO! improve this
    to_remove = []
    for name, module in sys.modules.items():
        if not module:
            continue
        try:
            if module.__file__.startswith(venv_dict["VIRTUAL_ENV"]):
                to_remove.append(name)
        except AttributeError:
            pass

    for name in to_remove:
        del sys.modules[name]


def install_dependencies(
    venv_path: Path, dependencies: list[str], *, pip_args: list[str] | None = None
) -> None:
    if not dependencies:
        return

    python_path = f"{venv_path}/{PYTHON_EXECUTABLE_PATH[os.name]}"

    cmd = [python_path, "-m", "pip", "install"]
    cmd.extend(dependencies)
    if pip_args:
        cmd.extend(pip_args)
    subprocess.run(cmd, check=True)


@contextmanager
def change_executable(executable: str):
    _executable = sys.executable

    sys.executable = executable
    sys._base_executable = sys.executable
    yield
    sys._base_executable = sys.executable = _executable


def get_context():
    if os.name == "nt":
        executable = Path(sys.base_prefix, "python.exe")
    elif os.name == "posix":
        # On Linux we use system python
        executable = Path(sys.base_prefix, "bin", "python3")
    else:
        # java/jython
        raise RuntimeError("Jython not supported (yet?)")
    return change_executable(str(executable))


@contextmanager
def venv_context(venv_path: Path, dependencies: list[str] | None = None):
    activate_venv(venv_path=venv_path, dependencies=dependencies)
    yield
    deactivate_venv()


def run_script_in_env(
    script_path: str | None = None,
    venv_path: Path | None = None,
    dependencies: list[str] | None = None,
) -> None:
    if not script_path:
        script_path = ida_kernwin.ask_file(
            0,
            "*.py|*.*",
            "Select script",
        )
    if not script_path:
        return

    script = Path(script_path).resolve()
    if not script.is_file():
        return

    parent_dir = os.environ.get("IDAVENV_VENV_DIR", str(script.parent))

    if not venv_path:
        venv_path = Path(parent_dir, f".venvs/{script.stem}")
    with venv_context(venv_path=venv_path, dependencies=dependencies):
        sys.path.append(parent_dir)
        runpy.run_path(str(script), run_name="__main__")


def _validate_file(filename):
    path = Path(filename).resolve()
    if path.is_file():
        return path

    raise argparse.ArgumentTypeError(f"{filename} is not a valid file")


@dataclass
class ModuleArgsNamespace:
    venv: Path | None = None
    dependencies: list[str] | None = None
    requirements_file: Path | None = None


def _parse_module_args(args: list[str]) -> ModuleArgsNamespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--venv", type=Path)

    dependencies_group = parser.add_mutually_exclusive_group()
    dependencies_group.add_argument("-r", "--requirements-file", type=_validate_file)
    dependencies_group.add_argument("-d", "--dependencies", nargs="*", type=str)

    namespace = ModuleArgsNamespace()
    parsed_args, _ = parser.parse_known_args(args, namespace=namespace)

    return parsed_args


def _process_module_args(args: ModuleArgsNamespace):
    if not args.venv:
        return

    dependencies = []
    if args.dependencies:
        dependencies = args.dependencies
    elif args.requirements_file:
        dependencies = [
            str(dep)
            for dep in pkg_resources.parse_requirements(
                args.requirements_file.read_text()
            )
        ]

    activate_venv(venv_path=args.venv, dependencies=dependencies)


class ActionDeclaration(TypedDict):
    name: str
    label: str
    handler: ida_kernwin.action_handler_t
    shortcut: NotRequired[str]
    tooltip: NotRequired[str]
    icon: NotRequired[int]
    flags: NotRequired[int]
    menu_location: str


class ActionHandler(ida_kernwin.action_handler_t):
    def __init__(self, name: str, callback) -> None:
        ida_kernwin.action_handler_t.__init__(self)
        self._name = name
        self._callback = callback

    def activate(self, ctx) -> None:
        self._callback()

    def update(self, ctx) -> bool:
        return ida_kernwin.AST_ENABLE_ALWAYS


def register_action(action: ActionDeclaration):
    ida_action = ida_kernwin.action_desc_t(
        action["name"],
        action["label"],
        action["handler"],
        action.get("shortcut", ""),
        action.get("tooltip", ""),
        action.get("icon", 0),
        action.get("flags", 0),
    )
    if not ida_kernwin.register_action(ida_action):
        print("Failed to register {action['id']}")

    if not ida_kernwin.attach_action_to_menu(
        action["menu_location"],  # The menu location
        action["name"],  # The unique function ID
        ida_kernwin.SETMENU_APP,  # Flags
    ):
        print(f"Failed to attach to menu { action['name']}")


def register_actions(actions: list[ActionDeclaration]):
    for action in actions:
        register_action(action=action)


class IDAVenvPlugin(ida_idaapi.plugin_t):
    # Use the HIDE flag to avoid the entry in
    # Edit/Plugins since this plugin's run()
    # method has no functionality...it's all
    # in the actions.

    flags = ida_idaapi.PLUGIN_HIDE
    comment = "Plugin to help with using venvs in IDA Pro."
    help = " See https://github.com/Skwteinopteros/ida-venv?tab=readme-ov-file#usage"
    wanted_name = "IDAVenv"
    wanted_hotkey = ""
    actions = [
        ActionDeclaration(
            name=f"{PLUGIN_NAME}:run",
            label="Script file in venv",
            handler=ActionHandler(
                name=f"{PLUGIN_NAME}:run", callback=run_script_in_env
            ),
            shortcut="Ctrl+Alt+F7",
            tooltip="Runs script in venv",
            menu_location="File/Script file...",
        )
    ]

    def init(self):
        print(f"[{PLUGIN_NAME}] initialization start")

        register_actions(actions=self.actions)
        args = ida_loader.get_plugin_options(PLUGIN_NAME)
        if args:
            parsed_args = _parse_module_args(args=args.split(":"))
            _process_module_args(args=parsed_args)

        print(f"[{PLUGIN_NAME}] initialization complete")
        # Return KEEP instead of OK to keep the
        # plugin loaded since it registers
        # callback actions and hotkeys
        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg):
        print(f"[{PLUGIN_NAME}] run (no effect)")

    def term(self):
        print(f"[{PLUGIN_NAME}] terminated")
        deactivate_venv()


def PLUGIN_ENTRY():
    plugin = IDAVenvPlugin()

    return plugin
