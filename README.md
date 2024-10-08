<!--
   SPDX-FileCopyrightText: 2024 ICS inc.
   SPDX-License-Identifier: CC-BY-SA-4.0
-->

ICS SBoM Libs ![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/integratedcomputersolutions/ics-sbom-libs/build.yml) [![REUSE status](https://api.reuse.software/badge/github.com/integratedcomputersolutions/ics-sbom-libs)](https://api.reuse.software/info/github.com/integratedcomputersolutions/ics-sbom-libs) [![PyPI - Version](https://img.shields.io/pypi/v/ics_sbom_libs)](https://pypi.org/project/ics-sbom-libs/) ![PyPI - Downloads](https://img.shields.io/pypi/dm/ics-sbom-libs)
===
This is re-usable python tools for working with SBoMs

## Description
This project contains libraries for working with SBoMs

### Installation
 Most users will want to use [SBOMGuard](https://sbomguard.com) or [icsbom](https://github.com/integratedcomputersolutions/icsbom) and not these libraries directly.
 
 Package are on pypi `pip install ics-sbom-libs`


### Development

We suggest a workflow involving the following tools:
- `pyenv` -- to manage python versions (and virtual environments on MacOS + Linux)
- `poetry` -- to manage dependency resolution, installation, building, packaging, publishing, and running of the code
- `pyinstaller` -- to build executables that can be ran without requiring a python installation on the target system

#### PYENV

##### Install PyEnv

1. MacOS: ``brew install pyenv``
2. Ubuntu:
   ```
   % sudo apt-get install -y make build-essential libssl-dev zlib1g-dev libbz2-dev libreadline-dev libsqlite3-dev wget
   curl llvm libncurses5-dev libncursesw5-dev xz-utils tk-dev libffi-dev liblzma-dev python-openssl git
   % curl https://pyenv.run | bash
   ...
   # This sets up pyenv into your profile
   % echo 'export PYENV_ROOT="$HOME/.pyenv"' >> ~/.bashrc
   % echo 'export PATH="$PYENV_ROOT/bin:$PATH"' >> ~/.bashrc
   % echo -e 'if command -v pyenv 1>/dev/null 2>&1; then\n eval "$(pyenv init -)"\nfi' >> ~/.bashrc
   ```
3. Windows: Follow instructions [here](https://github.com/pyenv-win/pyenv-win)
- PowerShell: give permission to execute scripts:
```
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine
```
- Install pyenv
```
Invoke-WebRequest -UseBasicParsing -Uri 'https://raw.githubusercontent.com/pyenv-win/pyenv-win/master/pyenv-win/install-pyenv-win.ps1' -OutFile "./install-pyenv-win.ps1"; \&'./install-pyenv-win.ps1'
```
- Disable Python App Installers: Start > "Manage App Execution Aliases" and turning off the "App Installer" aliases for Python
- Pyenv only exists on MacOS and Linux - the windows version is a fork which does not support the full functionality – e.g., it does not support creating virtual envs. Consider using the linux environment on windows (e.g., cygwin), and install the original pyenv.
- Sometimes PowerShell does not reflect the correct PATH variable (though set correctly in system env vars). In that case, set it manually:
```
$env:PATH='$HOME\.pyenv\pyenv-win\bin;' + $env:PATH
$env:PATH='$HOME\.pyenv\pyenv-win\shims;' + $env:PATH
```

##### Use PyEnv

- Checking for what versions of python are available to install
```
pyenv install --list
```

- Checking for what versions of python are installed
```
pyenv versions
```

- Install desired python version:
```
pyenv install 3.11
```

- Set the global python version
```
pyenv global 3.11
```

- Set the local (dependent on directory) python version
```
pyenv local 3.9
```

- Install pip (if it wasn’t already installed)
```
wget https://bootstrap.pypa.io/get-pip.py -OutFile get-pip.py
python ./get-pip.py
rm get-pip.py
```

#### POETRY

##### Install Poetry

- General installation instructions [here](https://lucasrla.github.io/python-on-macos/poetry.html#install-poetry-via-pipx)

1. Mac:
```bash
% brew install poetry
```
2. Ubuntu:
```bash
% sudo apt-get install pipx
% pipx install poetry
```

3. PowerShell:
```
(Invoke-WebRequest -Uri https://install.python-poetry.org -UseBasicParsing).Content | python -
```
- Add poetry’s bin dir to $PATH: `$HOME\AppData\Roaming\Python\Scripts`

_Limitations of pyenv/poetry on Windows (which DO NOT EXIST ON POSIX):_

- Pyenv cannot create virtual environment
- Pyenv does not install pip with the python version (must be installed manually)
- Poetry must be installed with the target python version (poetry does not respect the active environment selected with pyenv; this makes pyenv almost redundant)

##### Use Poetry

A few important commands using poetry are:

- Install python package: `poetry install`
- Update dependencies (resolving dependencies): `poetry lock`
- Run tools, e.g., black: `poetry run black .`
- Build package: `poetry build`
- Run a poetry script: `poetry run <script_name>`

Each `poetry run` creates a virtual environment in which the script is executed. If `pyenv` controls the virtual environments,
`poetry` should be configured to not create virtual environments. In this case, `poetry` will respect and use the pyenv virtual environment.


### NVD API Key
Downloading the NVD database into the cache can take a very long time.  To help with this they have created a way to use
an API key that will allow you to access the NVD database at a faster rate.  You can find the instructions to receive and
activate an API key [here](https://nvd.nist.gov/developers/request-an-api-key).

Once you have the API key you can copy it into the `cache_dir` (default: `${HOME}/.cache/icsbom`) in a file called `api_key.txt`.
Another way that you can use your API key is as an argument to the CLI tools using `--api_key ${your key}`.

