--------
Overview
--------

The scripts in the privileged parties folder can be used to extract privileged functions and their respective privileged parties from smart contract binaries. From that a graphical representation of the control structure of a smart contract can be build. The scripts can output a html graph, tikz representation, networkx graph and a csv representation. A seed set of contracts can be provided as a json file (see kitties.json)

Privileged functions are functions that can only be run by certain parties that have exceptional control over some parameters over the smart contract in question.

Installation
------------

Just install ethpector, all dependencies should be already available. To get csv
for the evaluation part pandas needs to be installed.


Run
---

The Json file in the folder defines the experiment seeds. Experiments can be run via
::

    python experiment.py [json seed file] [recursive (optional): bool; default=False] [nr_processes (optional): int; default=8]

This runs the experiment, and shows a summary in the end. The experiment writes all output to an special output folder, usually ethpector-output/[json filename without .json].

Evaluation
----------

Evaluation is run at the end of the experiment but can also be run standalone.
::

    python evaluate.py [output folder of the experiment] [include_without_code (optional): bool; default=False]

include_without_code allows you to ignore contracts that have no source available during calculation of recall, precision and f1


Visualization
-------------

The forest/graph resulting form an experiment can be visualized. Either as one graph or one graph per weakly connected component (per_component).
::

    python visualize.py  [output folder of the experiment] [per_component (optional): bool; default=False] [only_with_owners (optional): bool; default=False]

only_with_owners controls if all nodes should be printed or just those that have owners and their respective owners. This means that if the seed file contained addresses that have no owners those will not be printed if only_with_owners is true.


Tags
----

Meta information (such as names etc.) about addresses should be encoded in tags.json. The name are used to show human readable name in graphs and output files.

Other
-----

Some function signatures might be only available after running the experiment the second time. Ethpector parses signatures during the experiment from source code.

Config
------

We used the following config for our experiments. Note that in the current version of the experiment the parameters are not loaded from the .env file but hard coded into extract.py.

::

    ETHPECTOR_ETHERSCAN_TOKEN=[omitted]
    ETHPECTOR_RPC=[omitted]
    ETHPECTOR_CHAINID=1
    ETHPECTOR_MYTHRIL_EXECUTION_TIMEOUT=500
    ETHPECTOR_MYTHRIL_CREATE_TIMEOUT=60
    ETHPECTOR_MYTHRIL_MAX_DEPTH=512
    ETHPECTOR_MYTHRIL_SOLVER_TIMEOUT=200000
    ETHPECTOR_SENDER_CONSTRAINT_ENABLE_SENDER_IN_INDEX=TRUE
