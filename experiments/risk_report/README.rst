--------
Overview
--------

The risk_report produces a report about an smart contract laying summarizes risks involved regarding the interaction with a smart contract


Installation
------------

Additionally to ethpector a couple of other requriements are needed. Please install them using:
::

    pip install -r requriements.txt

Or a similar command suitable to your environment.

Configuration
------

Configure ethpector using an .env file.

::

    ETHPECTOR_ETHERSCAN_TOKEN=[omitted]
    ETHPECTOR_RPC=[omitted]
    ETHPECTOR_CHAINID=1
    ETHPECTOR_MYTHRIL_EXECUTION_TIMEOUT=500
    ETHPECTOR_MYTHRIL_CREATE_TIMEOUT=60
    ETHPECTOR_MYTHRIL_MAX_DEPTH=512
    ETHPECTOR_MYTHRIL_SOLVER_TIMEOUT=200000
    ETHPECTOR_SENDER_CONSTRAINT_ENABLE_SENDER_IN_INDEX=TRUE
