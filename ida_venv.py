import argparse
import json
import os
import runpy
import site
import subprocess
import sys
from contextlib import contextmanager
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


def activate_venv(venv_path: Path) -> None:
    base_path = str(venv_path.resolve())
    venv_dict = {
        "VIRTUAL_ENV": base_path,
        "_OLD_VIRTUAL_PATH": os.environ.pop("PATH", ""),
        "_OLD_PREFIX": sys.prefix,
    }

    try:
        bin_dir = f"{base_path}/{BIN_PATH[os.name]}"
    except KeyError:
        # java/jython
        raise RuntimeError("Jython not supported (yet?)")

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
    sys.prefix = sys.exec_prefix = venv_dict["VIRTUAL_ENV"]


def deactivate_venv() -> None:
    venv_dicts = json.loads(os.environ.get("IDAVenvs", "[]"))
    if not venv_dicts:
        return

    venv_dict = venv_dicts.pop()
    if not venv_dict:
        return

    # restore old path
    os.environ["PATH"] = os.environ.pop("_OLD_VIRTUAL_PATH", "")
    # restore prefix
    sys.prefix = sys.exec_prefix = venv_dict["_OLD_PREFIX"]
    os.environ["IDAVenvs"] = json.dumps(venv_dicts)


def install_dependencies(venv_path: Path, dependencies: list[str]) -> None:
    if not dependencies:
        return

    python_path = f"{venv_path}/{PYTHON_EXECUTABLE_PATH[os.name]}"

    cmd = [python_path, "-m", "pip", "install"]
    cmd.extend(dependencies)
    result = subprocess.run(cmd, capture_output=True)
    if result.returncode:
        print(result)


@contextmanager
def change_executable(executable: str):
    _executable = sys.executable

    sys.executable = executable
    sys._base_executable = sys.executable
    yield
    sys._base_executable = sys.executable = _executable


def get_context():
    if os.name == "nt":
        # On windows we can query the python executable used by ida
        import ida_registry

        executable = str(
            Path(ida_registry.reg_read_string("Python3TargetDLL")).parent
            / ("python.exe")
        )
    elif os.name == "posix":
        # On Linux we use system python
        executable = f"{sys.base_prefix}/bin/python3"
    else:
        # java/jython
        raise RuntimeError("Jython not supported (yet?)")
    return change_executable(executable)


def run_in_env(
    script: str | None = None, dependencies: list[str] | None = None
) -> None:
    if not script:
        script = ida_kernwin.ask_file(
            0,
            "*.py|*.*",
            "Select script",
        )
    if not script:
        return

    parent_dir = os.environ.get("WORKON_HOME", str(Path(script).parent))

    venv = Path(parent_dir, f".venvs/{Path(script).stem}")
    with get_context():
        create(venv, system_site_packages=True, symlinks=False, with_pip=True)

    activate_venv(venv_path=venv)

    if dependencies:
        install_dependencies(venv_path=venv, dependencies=dependencies)

    sys.path.append(parent_dir)
    runpy.run_path(script, run_name="__main__")
    deactivate_venv()


def _validate_file(filename):
    path = Path(filename).resolve()
    if path.is_file():
        return path

    raise argparse.ArgumentTypeError(f"{filename} is not a valid file")


def _process_module_args(args: list[str]):
    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--venv", type=Path)

    dependencies_group = parser.add_mutually_exclusive_group()
    dependencies_group.add_argument("-r", "--requirements-file", type=_validate_file)
    dependencies_group.add_argument("-d", "--dependencies", nargs="*", type=str)
    parsed_args, _ = parser.parse_known_args(args)

    if parsed_args.venv:
        with get_context():
            create(Path(parsed_args.venv), system_site_packages=True, symlinks=False)
        activate_venv(venv_path=Path(parsed_args.venv))

        if not (parsed_args.dependencies or parsed_args.requirements_file):
            return

        if parsed_args.dependencies:
            dependencies = parsed_args.dependencies
        elif parsed_args.requirements_file:
            dependencies = [
                str(dep)
                for dep in pkg_resources.parse_requirements(
                    parsed_args.requirements_file.read_text()
                )
            ]
        else:
            dependencies = []

        install_dependencies(venv_path=parsed_args.venv, dependencies=dependencies)


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
    comment = "A test plugin"
    help = "No help - this is just a test"
    wanted_name = "Hello World"
    wanted_hotkey = ""
    actions = [
        ActionDeclaration(
            name=f"{PLUGIN_NAME}:run",
            label="Script file in venv",
            handler=ActionHandler(name=f"{PLUGIN_NAME}:run", callback=run_in_env),
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
            _process_module_args(args=args.split(":"))

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
