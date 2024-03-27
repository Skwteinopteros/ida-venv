# IDAVenv

An IDAPYthon plugin to create and use virtual environments.

## Instalation

Copy (or link) `./ida_venv.py` to `$UDAUSR/plugins` user directory.
More info on the user directory:  https://hex-rays.com/blog/igors-tip-of-the-week-33-idas-user-directory-idausr/

## Usage

### Activate venv on plugin startup

This way the venv will be activated as soon as IDA loads the plugin,
and it will be automatically deactivated when the plugin is unloaded (at IDA exit).

Pass options to the module using the `-O` options flag when running 
IDA (https://hex-rays.com/products/ida/support/idadoc/1465.shtml).
        
```
Args:
    -v | --venv: path to venv. If it does not exist, it will be created
    -d | --dependencies: dependencies to install on the venv. Can have multiple values
    -r | --requirements: path to requirements file where dependencies will be read from

* -d and -r are mutually exclusive and are ignored if -v is not passed
```

Example:

```shell
# Activate venv on plugin startup and install 2 deps
~> ida -OIDAVenv:--venv:<path-to-venv>:-d:<dep1>:-d:<dep2> <path-to-binary>

# Activate venv on plugin startup and pass requirements file
~> ida -OIDAVenv:--venv:<path-to-venv>:-r:<path-to-requirements-file> <path-to-binary>

# Activate venv on plugin startup
~> ida -OIDAVenv:--venv:<path-to-venv> <path-to-binary>
```

### Use the API inside your script

You can use the provided API to create the venv in your script.

Example:

```python
import ida_venv
from pathlib import Path

venv_path = Path(Path.home(), ".venvs", "my_venv")


# create the venv
ida_venv.create_venv(venv_path)

# activate the venv
ida_venv.activate_venv(venv_path, dependencies=["dep1", "dep2"])

# Do ida stuff tha require the dependencies

# deactivate the venv [Optional if quiting ida]
ida_venv.deactivate_venv()
```

or using a context manager:

```python
import ida_venv
from pathlib import Path

venv_path = Path(Path.home(), ".venvs", "my_venv")

with ida_venv.venv_context(venv_path, dependencies=["dep1", "dep2"]):
    # Do ida stuff tha require the dependencies

```

### Use the provided convenience function

you can use the provided `run_script_in_env` function to run your script inside a venv
from the IDA repl console.

Example:

```python

# Create a new venv (if it doesn't exist), install dependencies and run the script
run_script_in_env(script_path="path-to-your-script", dependencies=["dep1", "dep2"])
```
