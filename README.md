<!--
   SPDX-FileCopyrightText: 2024 ICS inc.
   SPDX-License-Identifier: CC-BY-SA-4.0
-->

# Ics SBoM Tooling

This is re-usable python tools for working with SBoMs

## Description
This project contains libraries for working with SBoMs

## Development Environment

This project is managed using Python Poetry.  This is a build manager that also controls the virtual environments for
each project and the modules that are loaded in each virtual environment.  To setup the environment do the following:

### Installation

#### Prerequisites

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

###### Install Poetry

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

#### PYINSTALLER

###### Installing pyinstaller
```
% pip install pyinstaller
```

### Deployment

Using Poetry, the deployment of the SBoM tooling is quite easy.  Poetry supports two types of deployment: Wheel and SDist. These do not require poetry to be use[recipe-libtool-native.spdx.json](..%2F..%2F..%2F..%2FUsers%2Fmdingwall%2FDownloads%2Fspdx%2Fapalis-imx6%2Frecipes%2Frecipe-libtool-native.spdx.json)d and can be installed directly with either `pip` or `setup.py` respectively.

To deploy the project do the following:

```shell
% poetry build
```


### Getting Started

After getting poetry installed and running:

1. We need to make sure that `sql.h` is installed in the system on Ubuntu by installing `unixodbc-dev`: `% sudo apt-get install unixodbc-dev`
2. Do the following:

   ```shell
   [./ics_sbom_tooling] % pyenv install 3.11   
   [./ics_sbom_tooling] % pyenv local 3.11   
   [./ics_sbom_tooling] % poetry env use 3.11   
   (ics_sbom_tooling-py3.11) [./ics_sbom_tooling] % poetry install
   (ics_sbom_tooling-py3.11) [./ics_sbom_tooling] % 
   ```
   
   If you have already done the poetry environment setup for the project, you can just do the following when starting a new shell.

   ```shell
   [./ics_sbom_tooling] % poetry shell   
   (ics_sbom_tooling-py3.11) [./ics_sbom_tooling] % 
   ```
   
**NOTE**: If you are using JetBrains PyCharm, there may be some more setup required for making sure that the poetry environment is properly setup, but you should be able to open the cloned repo directory and the project should work.  It may complain about not having a python interpreter setup however.

### CLI Applications

Now that you are up and running there are two programs that you have access to through the poetry environment directly.  Any changes you make to them are immediately available to run with.  

#### nvd2db
The first application is `nvd2db`.  

This application simply creates the database cache file that we need to store the NVD data into.

#### icsbom
The second application is `icsbom`.

This application compares the contents of SBoM packages with the data in the NVD db file to get CVE information for each package in the SBoM.  It can then create a VEX file that is given to the `websbom` tool.  It also has the ability to interactively view the data found in the SBoM.

`icsbom` is currently focused on SBoM packages that are created using the Yocto SBoM generator flags.  The Yocto SBoM generator creates a directory that has 4 sets of files that are all in JSON SPDX format (this is yet another format being used for SBoM files).  These files are separated into 4 directories: by-namespace, recipes, packages, runtime.   When running with one of these SBoM packages from Yocto they are given to us in `*.tar.gz` form.  You don’t have to decompress that file to give them to `icsbom`.

### First Run
The first time you run either of the above applications, they will have to download the entire NVD database.  Both applications are capable of accomplishing this download as well as updating the cached NVD db.  They also have shared CLI arguments:  `--cache_dir` and `--db_file`.  These are optional args that you can define a different location or name for the NVD cached file. The defaults for them is `~/.cache/icsbom` and `nvd_v3.0.db` respectively.

**NOTE:** The `--cache_dir` is also the location that you can place the NVD API key if you have it.  The file name the API key needs to be in is `api_key.txt`. 

### Examples
Recommended examples:

```shell 
[./ics_sbom_tooling] % poetry shell
# the following command is an example with the defaults.
(ics_sbom_tooling-py3.11) [./ics_sbom_tooling] % python -m nvd2db 
# if you need to change the location of the cache dir or the db name you can do the following
(ics_sbom_tooling-py3.11) [./ics_sbom_tooling] % python -m nvd2db --cache_dir ~/.ics_cache --db_file nvd.db
# for icsbom this is the normal way to run the app 
(ics_sbom_tooling-py3.11) [./ics_sbom_tooling] % python -m icsbom -o ./sofia2v2-202310251806.json.vex -t "recipes" ./testdata/sofia2v2-spdx-202310251806.tgz
# and the following how to run it with the different cache dir or db name
(ics_sbom_tooling-py3.11) [./ics_sbom_tooling] % python -m icsbom --cache_dir ~/.ics_cache --db_file nvd.db -o ./sofia2v2-202310251806.json.vex -t "recipes" ./testdata/sofia2v2-spdx-202310251806.tgz
```

There are available `--help` CLI args that shows you more of the options available for each program. (edited)

### NVD API Key
Downloading the NVD database into the cache can take a very long time.  To help with this they have created a way to use
an API key that will allow you to access the NVD database at a faster rate.  You can find the instructions to receive and
activate an API key [here](https://nvd.nist.gov/developers/request-an-api-key).

Once you have the API key you can copy it into the `cache_dir` (default: `${HOME}/.cache/icsbom`) in a file called `api_key.txt`. 
Another way that you can use your API key is as an argument to the CLI tools using `--api_key ${your key}`.

