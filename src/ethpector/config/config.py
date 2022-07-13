import logging
import os
from dotenv import load_dotenv

log = logging.getLogger(__name__)
RECOGNIZED_OUTPUTS = [
    "summary",
    "disassembly",
    "sourcecode",
    "all",
    "basicblocks",
    "calls",
    "storage",
    "functions",
    "known_interfaces",
]


class Configuration:

    """
    Global configuration for ethpector.

    Attributes:
        mythril (MythrilConfiguration): Mythril specific setting (sym-exec)
    """

    def __init__(self, commandline_args):
        self._loglevel = commandline_args.loglevel
        self._deploy_code = commandline_args.deploy_code
        self._rpc = commandline_args.rpc
        self._etherscan_token = commandline_args.etherscan_token
        self._tofile = commandline_args.tofile
        self._output_dir = commandline_args.output_dir
        self._drop_metadata = commandline_args.dont_drop_metadatastring is None
        self._offline = commandline_args.offline
        self._outputs = (
            commandline_args.output if commandline_args.output else ["summary"]
        )

        self._nodotenv = commandline_args.nodotenv

        if self._nodotenv is None or self._nodotenv is False:
            log.debug("Loading .env")
            self.initialize_dotenv()

        for o in self._outputs:
            if o not in RECOGNIZED_OUTPUTS:
                log.warning(
                    f"Output mode {o} not recognized. "
                    "Possible values are: {RECOGNIZED_OUTPUTS}"
                )

        self.mythril = MythrilConfiguration(commandline_args)

    @staticmethod
    def default(
        loglevel=logging.WARNING,
        deploy_code=None,
        rpc=None,
        etherscan_token=None,
        tofile=None,
        output_dir="ethpector-output",
        dont_drop_metadatastring=None,
        offline=True,
        output=None,
        nodotenv=True,
        concolic=False,
        execution_timeout=None,
        max_depth=None,
        loop_bound=None,
        create_timeout=None,
        solver_timeout=None,
        call_depth_limit=None,
        transaction_count=None,
        sender_const_sender_in_index=None,
    ):
        from collections import namedtuple

        T = namedtuple(
            "MockConfig",
            [
                "loglevel",
                "deploy_code",
                "rpc",
                "etherscan_token",
                "tofile",
                "output_dir",
                "dont_drop_metadatastring",
                "offline",
                "output",
                "nodotenv",
                "concolic",
            ],
        )

        config = Configuration(
            T(
                loglevel=loglevel,
                deploy_code=deploy_code,
                rpc=rpc,
                etherscan_token=etherscan_token,
                tofile=tofile,
                output_dir=output_dir,
                dont_drop_metadatastring=dont_drop_metadatastring,
                offline=offline,
                output=output,
                nodotenv=nodotenv,
                concolic=concolic,
            )
        )

        if execution_timeout is not None:
            os.environ["ETHPECTOR_MYTHRIL_EXECUTION_TIMEOUT"] = str(execution_timeout)

        if max_depth is not None:
            os.environ["ETHPECTOR_MYTHRIL_MAX_DEPTH"] = str(max_depth)

        if loop_bound is not None:
            os.environ["ETHPECTOR_MYTHRIL_LOOP_BOUND"] = str(loop_bound)

        if create_timeout is not None:
            os.environ["ETHPECTOR_MYTHRIL_CREATE_TIMEOUT"] = str(create_timeout)

        if solver_timeout is not None:
            os.environ["ETHPECTOR_MYTHRIL_SOLVER_TIMEOUT"] = str(solver_timeout)

        if call_depth_limit is not None:
            os.environ["ETHPECTOR_MYTHRIL_CALL_DEPTH_LIMIT"] = str(call_depth_limit)

        if transaction_count is not None:
            os.environ["ETHPECTOR_MYTHRIL_TRANSACTION_COUNT"] = str(transaction_count)

        if sender_const_sender_in_index is not None:
            os.environ["ETHPECTOR_SENDER_CONSTRAINT_ENABLE_SENDER_IN_INDEX"] = str(
                sender_const_sender_in_index
            )

        return config

    def initialize_dotenv(self):
        load_dotenv()

    def loglevel(self):
        return self._loglevel if self._loglevel else logging.WARNING

    def deploy_code(self) -> bool:
        return self._deploy_code is not None

    def offline(self) -> bool:
        return self._offline is not None and self._offline

    def rpc_url(self) -> str:
        return self._rpc if self._rpc else os.getenv("ETHPECTOR_RPC")

    def is_rpc_set(self) -> bool:
        x = self.rpc_url()
        return x is not None and len(x) > 0

    def is_etherscan_token_set(self) -> bool:
        x = self.etherscan_token()
        return x is not None and len(x) > 0

    def output_dir(self) -> str:
        return (
            self._output_dir if self._output_dir else os.getenv("ETHPECTOR_OUTPUTDIR")
        )

    def etherscan_token(self) -> str:
        return (
            self._etherscan_token
            if self._etherscan_token
            else os.getenv("ETHPECTOR_ETHERSCAN_TOKEN")
        )

    def sourcify_base_url(self) -> str:
        return "https://sourcify.dev/"

    def drop_metadata_string_before_analysis(self) -> bool:
        env = os.getenv("ETHPECTOR_DROP_METADATASTRING")
        return bool(env) if env else self._drop_metadata

    def sender_const_sender_in_index(self) -> bool:
        env = os.getenv("ETHPECTOR_SENDER_CONSTRAINT_ENABLE_SENDER_IN_INDEX")
        return env.lower() == "true" if env else False

    def output_all(self) -> bool:
        return "all" in self._outputs

    def output_summary(self) -> bool:
        return "summary" in self._outputs or self.output_all()

    def output_disassembly(self) -> bool:
        return "disassembly" in self._outputs or self.output_all()

    def output_sourcecode(self) -> bool:
        return "sourcecode" in self._outputs or self.output_all()

    def output_basicblocks(self) -> bool:
        return "basicblocks" in self._outputs or self.output_all()

    def output_calls(self) -> bool:
        return "calls" in self._outputs or self.output_all()

    def output_storage(self) -> bool:
        return "storage" in self._outputs or self.output_all()

    def output_functions(self) -> bool:
        return "functions" in self._outputs or self.output_all()

    def output_known_interfaces(self) -> bool:
        return "known_interfaces" in self._outputs or self.output_all()

    def more_than_one_output(self) -> bool:
        return len(self._outputs) > 1 or self.output_all()

    def to_file(self) -> bool:
        return self._tofile is not None and self._tofile

    def chain_id(self) -> int:
        env = os.getenv("ETHPECTOR_CHAINID")
        return int(env) if env else 1

    def __repr__(self):
        return (
            f"{self.__class__.__name__}("
            f"loglevel={self.loglevel()}, "
            f"deploy_code={self.deploy_code()}, "
            f"rpc_url={self.is_rpc_set()}, "
            f"etherscan_token={self.is_etherscan_token_set()}, "
            f"output={self._outputs}, "
            f"to_file={self.to_file()}, "
            f"chain_id={self.chain_id()}, "
            f"offline={self.offline()}, "
            f"mythril={self.mythril}, "
            f"sourcify_base_url={self.sourcify_base_url()}, "
            f"sender_in_index={self.sender_const_sender_in_index()}"
            ")"
        )


class MythrilConfiguration:
    def __init__(self, commandline_args):
        self._mythril_concolic = commandline_args.concolic

    def concolic_exec(self) -> bool:
        return (
            self._mythril_concolic
            if self._mythril_concolic
            else bool(os.getenv("ETHPECTOR_MYTHRIL_CONCOLICEXEC"))
        )

    def strategy(self) -> str:
        # one of ["dfs", "bfs", "naive-random", "weighted-random"]
        env = os.getenv("ETHPECTOR_MYTHRIL_STRATEGY")
        return env if env else "bfs"

    def execution_timeout(self) -> int:
        env = os.getenv("ETHPECTOR_MYTHRIL_EXECUTION_TIMEOUT")
        return int(env) if env else 30

    def max_depth(self) -> int:
        env = os.getenv("ETHPECTOR_MYTHRIL_MAX_DEPTH")
        return int(env) if env else 128

    def loop_bound(self) -> int:
        env = os.getenv("ETHPECTOR_MYTHRIL_LOOP_BOUND")
        return int(env) if env else 5

    def create_timeout(self) -> int:
        env = os.getenv("ETHPECTOR_MYTHRIL_CREATE_TIMEOUT")
        return int(env) if env else 40

    def solver_timeout(self) -> int:
        # The maximum amount of time(in milli seconds) the solver
        # spends for queries from analysis modules
        env = os.getenv("ETHPECTOR_MYTHRIL_SOLVER_TIMEOUT")
        return int(env) if env else 10000

    def call_depth_limit(self) -> int:
        env = os.getenv("ETHPECTOR_MYTHRIL_CALL_DEPTH_LIMIT")
        return int(env) if env else 10

    def transaction_count(self) -> int:
        env = os.getenv("ETHPECTOR_MYTHRIL_TRANSACTION_COUNT")
        return int(env) if env else 3

    def __repr__(self):
        return (
            f"{self.__class__.__name__}("
            f"concolic_exec={self.concolic_exec()},"
            f"strategy={self.strategy()},"
            f"execution_timeout={self.execution_timeout()},"
            f"max_depth={self.max_depth()},"
            f"loop_bound={self.loop_bound()},"
            f"create_timeout={self.create_timeout()},"
            f"solver_timeout={self.solver_timeout()},"
            f"call_depth_limit={self.call_depth_limit()},"
            f"transaction_count={self.transaction_count()}"
            ")"
        )
