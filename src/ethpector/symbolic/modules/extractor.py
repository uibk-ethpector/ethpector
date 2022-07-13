import logging
from pyevmasm import instruction_tables, DEFAULT_FORK
from mythril.analysis.module.base import DetectionModule, EntryPoint
from mythril.laser.ethereum.state.global_state import GlobalState

# from mythril.laser.ethereum.transaction.transaction_models import (
#     ContractCreationTransaction,
# )
from ethpector.data.datatypes import (
    FunctionSummary,
    Call,
    StorageLoad,
    StorageWrite,
    Selfdestruct,
    ConditionalJump,
    UnconditionalJump,
    Revert,
    Return,
    Calldataload,
    Calldatacopy,
    MemoryWrite,
    MemoryLoad,
    Log,
    Push,
    Create,
    Create2,
    CALL_INSTRUCTION_LIST,
    LOG_INSTRUCTION_LIST,
    decompose_inst,
)


__author__ = "soad003"
__copyright__ = "soad003"
__license__ = "MIT"


log = logging.getLogger(__name__)


class RecoverData(DetectionModule):
    name = "Data recoverer"
    # swc_id = UNPROTECTED_SELFDESTRUCT
    description = "Recovers annotations from symbolic execution"
    entry_point = EntryPoint.CALLBACK

    def __init__(self):
        self.pre_hooks = [
            inst.name.replace(
                "GETPC", "PC"
            )  # pyevmasm calls the opcode GETPC and mythril PC
            for inst in instruction_tables[DEFAULT_FORK]
            # if inst.name != "GETPC"
        ]  # GETPC currently not supported by mythril
        super().__init__()
        self.public_functions = {}
        self.calls = []
        self.storage_reads = []
        self.storage_writes = []
        self.memory_reads = []
        self.memory_writes = []
        self.logs = []
        self.returns = []
        self.reverts = []
        self.calldataloads = []
        self.calldatacopies = []
        self.selfdestructs = []
        self.conditional_jumps = []
        self.unconditional_jumps = []
        self.pushes = []
        self.creates = []
        self.create2s = []
        self.seen_pcs = set()

    def get_annotations(self):
        return (
            self.calls
            + self.storage_reads
            + self.storage_writes
            + self.memory_reads
            + self.memory_writes
            + self.logs
            + self.returns
            + self.reverts
            + self.calldataloads
            + self.calldatacopies
            + self.selfdestructs
            + self.unconditional_jumps
            + self.unconditional_jumps
            + self.pushes
            + self.creates
            + self.create2s
        )

    # def reset_module(self):
    #     super().reset_module()

    def _execute(self, state: GlobalState) -> None:
        if state.get_current_instruction()["address"] in self.cache:
            return
        else:
            self.cache |= {state.get_current_instruction()["address"]}
            self.seen_pcs.add(state.get_current_instruction()["address"])

        self._analyze_state(state)

    def _analyze_state(self, state):
        op, pc, instruction, stack, func, _ = decompose_inst(state)

        if func == "constructor" or state.environment.sender.symbolic is False:
            log.debug(
                "Looks like we are in a contract creation transaction "
                "or in a call. This module is only concerned with the "
                "code of the root contract, skipping."
            )
            return

        if func not in self.public_functions:
            self.public_functions[func] = FunctionSummary(name=func)

        self.public_functions[func].update(state)

        if op in CALL_INSTRUCTION_LIST:
            self.calls.append(Call.from_statespace(state))

        if op in ["SSTORE"]:
            self.storage_writes.append(StorageWrite.from_statespace(state))

        if op in ["SLOAD"]:
            self.storage_reads.append(StorageLoad.from_statespace(state))

        if op in ["MSTORE"]:
            self.memory_writes.append(MemoryWrite.from_statespace(state))

        if op in ["MLOAD"]:
            self.memory_reads.append(MemoryLoad.from_statespace(state))

        if op in ["RETURN"]:
            self.returns.append(Return.from_statespace(state))

        if op in ["REVERT"]:
            self.reverts.append(Revert.from_statespace(state))

        if op in ["SELFDESTRUCT"]:
            self.selfdestructs.append(Selfdestruct.from_statespace(state))

        if op in ["CALLDATALOAD"]:
            self.calldataloads.append(Calldataload.from_statespace(state))

        if op in ["CALLDATACOPY"]:
            self.calldatacopies.append(Calldatacopy.from_statespace(state))

        if op in ["JUMP"]:
            self.unconditional_jumps.append(UnconditionalJump.from_statespace(state))

        if op in ["JUMPI"]:
            self.conditional_jumps.append(ConditionalJump.from_statespace(state))

        if "PUSH" in op:
            self.pushes.append(Push.from_statespace(state))

        if "CREATE2" == op:
            self.create2s.append(Create2.from_statespace(state))

        if "CREATE" == op:
            self.creates.append(Create.from_statespace(state))

        if op in LOG_INSTRUCTION_LIST:
            self.logs.append(Log.from_statespace(state))

        return []
