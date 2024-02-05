# IDAVenv

## Instalation

Copy (or link) `./ida_venv.py` to `$UDAUSR/plugins` user directory.
More info on the user directory:  https://hex-rays.com/blog/igors-tip-of-the-week-33-idas-user-directory-idausr/

## Usage

### Start IDA inside a venv

You can pass options to the module using the `-O` options flag when running 
IDA (https://hex-rays.com/products/ida/support/idadoc/1465.shtml).
        
Args:
    -v | --venv: path to venv. If it does not exist, it will be created
    -d | --dependencies: dependencies to install on the venv. Can have multiple values
    -r | --requirements: path to requirements file where dependencies will be read from

Example:

    ```shell
    # Start IDA inside a venv and install networkx
    ida -OIDAVenv:--venv:<path-to-venv>:-d:networkx <path-to-binary>

    # Start IDA inside a pre-existing venv
    ida -OIDAVenv:--venv:<path-to-venv> <path-to-binary>
    ```
### Use the API inside your script

You can use the provided API to create the venv in your script.

Example:

```python

import ida_venv
import venv
from pathlib import Path

venv_path = Path(Path.home(), ".venvs", "my_venv")


# create the venv
with ida_venv.get_context():
    venv.create(venv_path, system_site_packages=True, symlinks=False, with_pip=True)

# activate the venv
ida_venv.activate_venv(venv_path)

# install dependencies
ida_venv.install_dependencies(venv_path, ["networkx"])


# Do ida stuff tha require networkx

# deactivate the venv [Optional]
ida_venv.deactivate_venv()
```

### Use the provided convinience function

you can use the provided `run_in_env` function to run your script inside a venv
from the IDA repl console.

Example:

```python

# Create a new venv (if it doesn't exist), install dependencies a and run the script
run_in_env(script="path-to-your-script", dependencies=["dep1", "dep2"])
```

