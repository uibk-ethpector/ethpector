import logging
from typing import Optional
from functools import lru_cache
from mythril.mythril import MythrilAnalyzer, MythrilDisassembler
from mythril.exceptions import DetectorNotFoundError, CriticalError
from mythril.analysis.module import ModuleLoader
from ethpector.data import SymbolicExecSummary
from ethpector.classify import InterfaceMatch, ContractClassifier, FunctionDefinition
from ethpector.utils import get_function_selector
from .modules.sender import MsgSender
from .modules.extractor import RecoverData

log = logging.getLogger(__name__)


class SymbolicAnalyzer:
    def __init__(self, code, address, online_resolver, config):
        self.address = address
        self.code = code
        self.online_resolver = online_resolver
        self.config = config
        self.classifier = ContractClassifier()

    @lru_cache(maxsize=1)
    def get_summary(self) -> Optional[SymbolicExecSummary]:
        disassembler = MythrilDisassembler(
            enable_online_lookup=not self.config.offline(),
            eth=self.online_resolver.get_mythril_rpc_lookup()
            if not self.config.offline()
            else None,
        )
        address, contract = disassembler.load_from_bytecode(
            self.code, bin_runtime=not self.config.deploy_code(), address=self.address
        )

        recover = RecoverData()
        sender = MsgSender(
            enable_sender_in_index=self.config.sender_const_sender_in_index()
        )
        loader = ModuleLoader()
        loader._modules.clear()  # clear the mythril internal modules
        loader.register_module(recover)
        loader.register_module(sender)

        # strategy = one of ["dfs", "bfs", "naive-random", "weighted-random"]
        function_analyzer = MythrilAnalyzer(
            strategy=self.config.mythril.strategy(),
            disassembler=disassembler,
            address=address,
            use_onchain_data=self.config.mythril.concolic_exec(),
            max_depth=self.config.mythril.max_depth(),
            execution_timeout=self.config.mythril.execution_timeout(),  # in sec
            loop_bound=self.config.mythril.loop_bound(),
            create_timeout=self.config.mythril.create_timeout(),
            # enable_iprof=False,
            # disable_dependency_pruning=True,
            solver_timeout=self.config.mythril.solver_timeout(),
            parallel_solving=True,
            # custom_modules_directory="test",
            call_depth_limit=self.config.mythril.call_depth_limit(),
            # sparse_pruning=False,
            # unconstrained_storage=True,
            # solver_log=None,  # folder name
        )
        try:
            _ = function_analyzer.fire_lasers(
                modules=None, transaction_count=self.config.mythril.call_depth_limit()
            )

            # if len(report.exceptions) > 0:
            #     log.error(report.exceptions)

            # add tags
            for call in recover.calls:
                if call.is_call_to_precompile():
                    call.set_tag("is_call_to_precompile", True)

                payload = call.get_calldata_hex()
                selector = get_function_selector(payload)
                if selector is not None:
                    r = self.online_resolver.function_name(selector)
                    if r:
                        for source, signatues in r.items():
                            flat_signatures = [
                                y for x in signatues for y in x.split(" or ")
                            ]
                            for sign in flat_signatures:
                                try:
                                    fd = FunctionDefinition(sign)
                                    parsed = fd.decode_input_to_str(payload)
                                    if parsed:
                                        call.set_tag("parsed_call", parsed)
                                except Exception as e:
                                    log.warning(
                                        "Failed to parse ABI for "
                                        "selector {} and signature {}: "
                                        "{}".format(selector, sign, e)
                                    )

            return SymbolicExecSummary(
                functions=list(recover.public_functions.values()),
                calls=recover.calls,
                storage_reads=recover.storage_reads,
                storage_writes=recover.storage_writes,
                memory_reads=recover.memory_reads,
                memory_writes=recover.memory_writes,
                logs=recover.logs,
                returns=recover.returns,
                reverts=recover.reverts,
                conditional_jumps=recover.conditional_jumps,
                unconditional_jumps=recover.unconditional_jumps,
                calldataloads=recover.calldataloads,
                calldatacopies=recover.calldatacopies,
                selfdestructs=recover.selfdestructs,
                pushes=recover.pushes,
                creates=recover.creates,
                create2s=recover.create2s,
                sender_constraint_functions=sender.sender_constraint_function,
                unique_instructions_visited=len(recover.seen_pcs),
            )

        except DetectorNotFoundError as e:
            log.error(format(e))
        except CriticalError as e:
            log.error("Analysis error encountered: " + format(e))

        return None

    def get_interface_matches(self, threshold=0.2) -> list[InterfaceMatch]:
        c = self.get_summary()
        functions = [y for x in c.functions for y in x.functions() if y != "fallback"]
        events = [
            hex(x.topic0.concrete_val()) for x in c.logs if not x.topic0.is_symbolic()
        ]
        constants = [hex(x.value) for x in c.pushes]

        return self.classifier.get_interface_matches(
            functions=functions, events=events, constants=constants, threshold=threshold
        )
