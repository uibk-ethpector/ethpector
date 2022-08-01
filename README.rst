.. _Stackoverflow: https://stackoverflow.com/questions/21530577/fatal-error-python-h-no-such-file-or-directory

.. _venv: https://docs.python.org/3/library/venv.html

.. image:: https://github.com/uibk-ethpector/ethpector/raw/main/misc/logo.png
   :target: https://github.com/uibk-ethpector/ethpector/raw/main/misc/logo.png
   :align: center
   :alt: logo
   :width: 50px



.. image:: https://github.com/uibk-ethpector/ethpector/actions/workflows/tests.yaml/badge.svg
    :target: https://github.com/uibk-ethpector/ethpector/actions/workflows/tests.yaml
    :alt: tests

.. image:: https://github.com/uibk-ethpector/ethpector/actions/workflows/docs.yaml/badge.svg
    :target: https://github.com/uibk-ethpector/ethpector/actions/workflows/docs.yaml
    :alt: docs


.. image:: https://img.shields.io/pypi/v/ethpector.svg
    :target: https://pypi.org/project/ethpector/
    :alt: pypi-version
=========
Ethpector
=========

    Ethpector extracts useful information from smart contract binaries.


Smart contracts are computer programs that coordinate financial agreements on blockchain systems. Although smart contract platforms are transparent in general smart contracts can be pretty opaque if their source-code is not available.

Ethpector sets out to provide tools to analyze smart contract with and without access to their source-code. Its main focus is to provide tools and heuristics for the automated analysis and classification of smart contracts.

Currently the tool enables:

- Fetching code by addresses (via web3 rpc)
- Fetching source-code for addresses (Etherscan and Sourcify)
- Recovering interfaces including logs from binaries
- Resolving function and event selectors (via 4bytes and more)
- It uses control-flow analysis and symbolic execution (mythril) to extract data like calls, stores, logs, etc. including parameters if possible
- It creates annotated disassembly
- It simple contract classification method based on interfaces and bytecode

For a more advanced example of how to use this data look at the examples in the experiments folder.

Usage
=====

To install run
::

    > pip install ethpector

or build from source directly by

::

    > make install

Use as follows:
::

    usage: ethpector [-h] [--version] [-r rpc] [-e etherscan_token] [-c] [-v] [-vv] [-d] [-a] [-f] [--dont_drop_metadatastring] [--output OUTPUT [OUTPUT ...]] [--output_dir OUTPUT_DIR] contract

    ethpector -- getting insights into evm binaries.

    positional arguments:
      contract              EVM input bytecode or address if -a is provided

options:
  -h, --help                                        show this help message and exit.
  --version                                         show program's version number and exit.
  -r rpc, --rpc rpc                                 Ethereum node RPC url.
  -e etherscan_token, --etherscan etherscan_token   Etherscan access token.
  -c, --concolic                                    Symbolic execution engine loads values (storage state, call targets) from a node via RPC.
  -v, --verbose                                     set loglevel to INFO.
  -vv, --very-verbose                               set loglevel to DEBUG.
  -d, --deploy                                      Sets if deployment code is provided. EXPERIMENTAL.
  -a, --address                                     Analyse address: data is loaded either via RPC or Etherscan.
  -f, --tofile                                      Dump output as files.
  --offline                                         Do not use any online resources.
  --nodotenv                                        Do not load dotenv file to initialize config values.
  --dont_drop_metadatastring                        Includes the metadata string to the bytecode analysis.
  --output OUTPUT                                   Output that should be produced: summary|disassembly|sourcecode|all|basicblocks|calls|storage|functions|known_interfaces. Note: Multiple OUTPUTS possible.
  --output_dir OUTPUT_DIR                           Directory to save the results if -f is specified. Default is ethspector-output/.

For improved analysis results bot an etherscan api token as well as a ethereum node is beneficial.
They can either be configured via commandline options (--rpc and --etherscan), via environment variables or .env files.

An example .env file could look as follows:
::

    ETHPECTOR_ETHERSCAN_TOKEN=[YOUR ETHERSCAN TOKEN]
    ETHPECTOR_RPC=https://mainnet.infura.io/v3/[YOUR INFURA TOKEN]
    ETHPECTOR_CHAINID=1
    ETHPECTOR_MYTHRIL_EXECUTION_TIMEOUT=100
    ETHPECTOR_MYTHRIL_CREATE_TIMEOUT=60
    ETHPECTOR_MYTHRIL_MAX_DEPTH=512
    ETHPECTOR_MYTHRIL_SOLVER_TIMEOUT=200000

A full list of configurable options can be found in src/ethpector/config/config.py.

The example folder holds some interesting binaries as well as addresses to test on.

Development
===========

it is advised to use a virtual environment (venv) for development. Run the following command to initialize one
::

    > python3 -m venv .venv

and activate it (in bash) using

::

    > source .venv/bin/activate

 For more information refer to (venv_). Run

::

    > make dev

to initialize the dev environment.
If you want to install ethpector in development mode run

::

    > make install-dev

Before committing anything to the repository please format, lint and test your code in that order. Fix all linter warnings and make sure all test are passing before a commit.

Use the following commands for that:
::

    > make format
    > make lint
    > make test

or equivalently run
::

    > make pre-commit

Some slow tests are excluded when running make test. Occasionally, one should run
::

    > make test-all

to run the entire test-suite.


Linting and formatting should be automatically executed on every git commit, using pre-commit.

To create the documentation please run:
::

    > make docs

Creating the docs need python dev dependencies to build see (Stackoverflow_)


Credits
=======

We thank all the developers of mythril for their great work. Without which this project would not exist.

 - `Mythril <https://github.com/ConsenSys/mythril>`_

We would like to thank the following projects for inspiration.

 - `Evmdis <https://github.com/Arachnid/evmdis>`_
 - `gsalzer s ethutils <https://github.com/gsalzer/ethutils/blob/main/ethutils/section.py>`_

Similar Projects
================

The following section contains a couple of similar projects and useful libraries that could serve as an alternative or to amend ethpector when analyzing smart contract binaries.

 - `eveem <https://eveem.org/api/>`_
 - `pakala <https://www.palkeo.com/en/projets/ethereum/pakala.html>`_
 - `manticore <https://github.com/trailofbits/manticore>`_
 - `panoramix decompiler <https://github.com/palkeo/panoramix>`_
 - `hevm <https://github.com/dapphub/dapptools>`_
 - `ethtx <https://github.com/ethtx/ethtx>`_
 - `slither <https://github.com/crytic/slither>`_

Funding
=======

This project was created in the course of the KRYPTOMONITOR project.

    The security research project KRYPTOMONITOR is funded by the Austrian
    security research programme KIRAS of the Federal Ministry of Agriculture,
    Regions and Tourism (BMLRT).

- `Kryptomonitor Project <https://kryptomonitor-project.info/>`_
