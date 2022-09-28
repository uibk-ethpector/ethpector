import json
import logging
import eth_abi  # TODO: use for log res. see user_assertion.py mythril
from dataclasses import dataclass, field
from datetime import date, time
from mythril.analysis.ops import VarType, get_variable, Variable
from mythril.laser.ethereum.state.global_state import GlobalState
from mythril.laser.ethereum.natives import PRECOMPILE_COUNT
from mythril.laser.smt import BitVec
from ethpector.utils import to_int, truncate_str
from typing import Optional

CALL_INSTRUCTION_LIST = ["CALL", "DELEGATECALL", "CALLCODE", "STATICCALL"]
STATE_READ_WRITE_INSTRUCTION_LIST = ["SSTORE", "SLOAD", "CREATE", "CREATE2"]
LOG_INSTRUCTION_LIST = ["LOG0", "LOG1", "LOG2", "LOG3", "LOG4"]
TERMINATOR_INSTRUCTIONS_LIST = [
    "RETURN",
    "STOP",
    "INVALID",
    "JUMP",
    "JUMPI",
    "SELFDESTRUCT",
    "REVERT",
]

log = logging.getLogger(__name__)


def default_json_encoder(o):
    # it's a date, time, or datetime
    if isinstance(o, (date, time)):
        return o.isoformat()

    if isinstance(o, int):
        return hex(o)

    if isinstance(o, set):
        return list(o)

    if isinstance(o, bytes):
        return o.hex()

    # never serialize global state
    if isinstance(o, GlobalState):
        return None

    if isinstance(o, SymbolicVariable):
        return repr(o)

    if isinstance(o, SymbolicMemorySlice):
        return repr(o)

    if isinstance(o, SymbolicExpression):
        return repr(o)

    # it's a Python class (with a `__dict__` attribute)
    if isinstance(type(o), type) and hasattr(o, "__dict__"):
        x = o.__dict__.copy()
        x.pop("state", None)  # remove state from dict
        return x

    # print a warning and return a null
    log.error(f"Json encoder couldn't find an encoder for: {o!r}, type={type(o)}")
    return "SERIALISATION ERROR"


def to_json(obj, encoder=default_json_encoder):
    return json.dumps(obj, indent=4, default=default_json_encoder)


class ToJsonDecorator:
    def __init__(self, c):
        self.c = c

    def __call__(self, *args, **kwargs):
        def _to_json(self, encoder=default_json_encoder):
            return to_json(self, encoder=encoder)

        self.c.to_json = to_json
        return self.c(*args, **kwargs)


def decompose_inst(state: GlobalState, enforce_instruction=None):
    """Helper to extract the current state and instruction for a
    sym-exec state

    Args:
        state (GlobalState): Sym-exec state we are in
        enforce_instruction (None, optional): If set to Instruction name,
        throws if called in a state with a different instruction.

    Returns:
        tuple: (op, address, instruction, stack, function, last_op)

    Raises:
        Exception: If called in the wrong context and enforce_instruction is
        set
    """
    instruction = state.get_current_instruction()
    op = instruction["opcode"]
    if enforce_instruction:
        if not op == enforce_instruction:
            raise Exception(
                "{} is not a {} instruction".format(op, enforce_instruction)
            )
    address = instruction["address"]
    stack = state.mstate.stack
    func = state.environment.active_function_name
    lastOp = (
        state.environment.code.instruction_list[state.mstate.pc - 1]["opcode"]
        if state.mstate.pc - 1 >= 0
        else None
    )
    return (op, address, instruction, stack, func, lastOp)


@dataclass
class AccountSummary:

    """
    Basic summary of current account state of an address.
    """

    is_contract: bool
    balance: int
    ens_name: str


class SymbolicMemorySlice:

    """
    Representation of a slice of memory in sym-exec.
    Data can be symbolic.

    Parameters:
        length (SymbolicVariable): Length of the slice
        mem (object): The slice itself, can be none if length or
            start are symbolic
        start (SymbolicVariable): Start position of the memory slice
    """

    mem: object
    start: object
    length: object

    def __init__(self, mem, start, length):
        self.mem = mem
        self.start = start
        self.length = length

    def try_decode_abi(self, types=["bool", "string"]):
        if not self.is_concrete():
            return None
        b = bytes(self.mem)
        bs = b.hex()

        # Error(string) used for revert strings
        if bs.startswith("08c379a0"):
            try:
                s = eth_abi.abi.decode_abi(["string"], b[4:])
                if s and len(s) > 0:
                    return s[0]
            except Exception as e:
                log.debug("Abi decoding failed: {} with {}".format(bs, e))
                pass

        for x in types:
            try:
                message = eth_abi.decode_single(
                    x,
                    b,
                )
                return str(message)
            except Exception as e:
                log.debug("Abi decoding failed: {}".format(e))
                continue
        return None

    def is_concrete(self):
        return (
            self.mem is not None
            and type(self.mem) == list
            and all(map(lambda x: type(x) == int, self.mem))
        )

    def is_concrete_selector(self):
        if self.mem is None or len(self.mem) < 4:
            return None
        m = self.mem[:4]
        return (
            m is not None and type(m) == list and all(map(lambda x: type(x) == int, m))
        )

    def concrete_val_selector(self):
        if self.mem is None or len(self.mem) < 4:
            return None
        return bytes(self.mem[:4]) if self.is_concrete_selector() else None

    def is_symbolic(self):
        return not self.is_concrete()

    def concrete_val(self):
        return bytes(self.mem) if self.is_concrete() else None

    def empty(self):
        return self.mem is None or len(self.mem) == 0

    def __str__(self):
        return truncate_str(self.__repr__(), 100)

    def __repr__(self):
        if self.is_concrete():
            x = self.try_decode_abi()
            return "{}".format(bytes(self.mem).hex()) if not x else x
        elif self.mem and type(self.mem) == BitVec and not self.mem.symbolic:
            return repr(self.mem).replace("\n", "").replace(" ", "")
        elif self.mem:
            return f"s({type(self.mem)})@({self.start}, {self.length})"
        else:
            return f"s({self.start}) - s({self.length})"


class SymbolicExpression:
    condition: object

    def __init__(self, condition):
        self.condition = condition

    def __str__(self):
        return truncate_str(self.__repr__(), 100)

    def __repr__(self):
        if type(self.condition) == BitVec:
            return repr(self.condition).replace("\n", "").replace(" ", "")
        else:
            return f"s({type(self.condition.val)})"


class SymbolicVariable:
    var: Variable

    def __init__(self, variable):
        self.raw = variable
        self.var = get_variable(variable)

    def is_symbolic(self):
        return self.var.type != VarType.CONCRETE

    def val(self):
        return self.var.val

    def concrete_val(self):
        return self.val() if not self.is_symbolic() else None

    def empty(self):
        return False

    def __str__(self):
        return truncate_str(self.__repr__(), 100)

    def __repr__(self):
        if self.var.type == VarType.CONCRETE:
            return f"{hex(self.var.val)}"
        elif type(self.var.val) == BitVec and not self.var.val.symbolic:
            return f"{self.var.val}"
        elif type(self.var.val) == BitVec:
            return repr(self.var.val).replace("\n", "").replace(" ", "")
        else:
            return f"s({type(self.var.val)})"


def decode_memory(
    state: GlobalState, meminstart: SymbolicVariable, meminsz: SymbolicVariable
) -> SymbolicMemorySlice:
    """Tries to decode a slice of memory extracted during symbolic execution.

    Args:
        state (GlobalState): State of we are in in sym-exec
        meminstart (SymbolicVariable): Representation of the start index
        (symbolic or concrete)
        meminsz (SymbolicVariable): Representation of the length of the slice
        (symbolic or concrete)

    Returns:
        SymbolicMemorySlice: Slice of data.
    """
    if not meminstart.is_symbolic() and not meminsz.is_symbolic():
        return SymbolicMemorySlice(
            state.mstate.memory[
                meminstart.val() : meminstart.val() + meminsz.val()  # * 4
            ],
            meminstart,
            meminsz,
        )
    else:
        return SymbolicMemorySlice(None, meminstart, meminsz)


@dataclass(init=False, eq=False, order=False, unsafe_hash=False)
class AnnotationBase:

    tags: dict

    def __init__(self):
        self.tags = {}

    def set_tag(self, key: str, tag: object):
        self.tags[key] = tag

    def __hash__(self):
        return id(self)

    def __eq__(self, other):
        return id(self) == id(other)

    def valid_at(self, pc) -> bool:
        return NotImplementedError("Not implemented")


@dataclass(init=False, eq=False, order=False, unsafe_hash=False)
class MetaDataString(AnnotationBase):
    raw: object
    index: int
    data: object
    url: str

    def __init__(self, raw, index, data, url):
        super().__init__()
        self.raw, self.index, self.data, self.url = (raw, index, data, url)

    def valid_at(self, pc) -> bool:
        if self.raw is None:
            return False
        return pc >= self.index


@dataclass(init=False, eq=False, order=False, unsafe_hash=False)
class PCAnnotation(AnnotationBase):
    pc: int

    def __init__(self, pc):
        super().__init__()
        self.pc = pc

    def valid_at(self, pc) -> bool:
        return pc == self.pc

    def get_pc(self) -> int:
        return self.pc


@dataclass(
    init=False, repr=True, eq=False, order=False, unsafe_hash=False, frozen=False
)
class JumpTarget(PCAnnotation):
    target: int

    def target_int(self) -> int:
        return self.target

    def __init__(self, pc, target):
        super().__init__(pc=pc)
        self.target = target


@dataclass(
    init=False, repr=True, eq=False, order=False, unsafe_hash=False, frozen=False
)
class FunctionEntrypoint(PCAnnotation):
    function_name: str

    def functions(self):
        return self.function_name.split(" or ")

    def functions_string(self):
        return self.function_name

    def __init__(self, pc, function_name):
        super().__init__(pc=pc)
        self.function_name = function_name


@dataclass(
    init=False, repr=True, eq=False, order=False, unsafe_hash=False, frozen=False
)
class SymbolicAnnotation(PCAnnotation):
    def __init__(self, state):
        _, pc, instuction, _, func, _ = decompose_inst(state)
        super().__init__(pc)
        self.state = state

    def opcode(self):
        _, _, instruction, _, _, _ = decompose_inst(self.state)
        return instruction["opcode"]

    def argument(self):
        _, _, instruction, _, _, _ = decompose_inst(self.state)
        return instruction["argument"]

    def functions(self):
        return self.state.environment.active_function_name.split(" or ")

    def functions_string(self):
        return self.state.environment.active_function_name

    def stack(self):
        return self.state.mstate.stack


@dataclass(
    init=False, repr=True, eq=False, order=False, unsafe_hash=False, frozen=False
)
class Call(SymbolicAnnotation):
    to: SymbolicVariable
    gas: SymbolicVariable
    type: SymbolicVariable
    value: SymbolicVariable
    data: SymbolicMemorySlice

    @classmethod
    def from_statespace(cls, state: GlobalState):
        op, _, _, stack, _, _ = decompose_inst(state)

        if op not in CALL_INSTRUCTION_LIST:
            raise Exception("{} is not a call instruction".format(op))

        if op in ["CALL", "CALLCODE"]:
            gas, to, value, meminstart, meminsz, _, _ = (
                SymbolicVariable(stack[-1]),
                SymbolicVariable(stack[-2]),
                SymbolicVariable(stack[-3]),
                SymbolicVariable(stack[-4]),
                SymbolicVariable(stack[-5]),
                SymbolicVariable(stack[-6]),
                SymbolicVariable(stack[-7]),
            )

            return Call(
                state, op, to, gas, value, decode_memory(state, meminstart, meminsz)
            )

        else:
            gas, to, meminstart, meminsz, _, _ = (
                SymbolicVariable(stack[-1]),
                SymbolicVariable(stack[-2]),
                SymbolicVariable(stack[-3]),
                SymbolicVariable(stack[-4]),
                SymbolicVariable(stack[-5]),
                SymbolicVariable(stack[-6]),
            )

            return Call(
                state, op, to, gas, data=decode_memory(state, meminstart, meminsz)
            )

    def __init__(self, state, _type, to, gas, value=SymbolicVariable(0), data=None):
        super().__init__(state)
        self.to = to
        self.gas = gas
        self.type = _type
        self.value = value
        self.data = data

    def is_call_to_precompile(self):
        return not self.to.is_symbolic() and 0 < self.to.val() <= PRECOMPILE_COUNT

    def get_calldata(self):
        return (
            self.data.concrete_val() if self.data and self.data.is_concrete() else None
        )

    def get_calldata_selector(self):
        return (
            self.data.concrete_val_selector()
            if self.data and self.data.is_concrete_selector()
            else None
        )

    def get_calldata_hex(self):
        d = self.get_calldata()
        return d.hex() if d else None

    def get_calldata_selector_hex(self):
        d = self.get_calldata_selector()
        return d.hex() if d else None


@dataclass(
    init=False, repr=True, eq=False, order=False, unsafe_hash=False, frozen=False
)
class Push(SymbolicAnnotation):
    value: int

    def __init__(self, state, value):
        super().__init__(state)
        self.value = to_int(value)

    @classmethod
    def from_statespace(cls, state: GlobalState):
        op, _, instruction, stack, _, _ = decompose_inst(state)

        if "PUSH" not in op:
            raise Exception("{} is not a PUSH instruction".format(op))
        return cls(state, instruction["argument"])


@dataclass(
    init=False, repr=True, eq=False, order=False, unsafe_hash=False, frozen=False
)
class StorageLoad(SymbolicAnnotation):
    slot: SymbolicVariable

    def __init__(self, state, slot):
        super().__init__(state)
        self.slot = slot

    @classmethod
    def from_statespace(cls, state: GlobalState):
        op, _, _, stack, _, _ = decompose_inst(state, "SLOAD")
        adr = SymbolicVariable(stack[-1])
        return cls(state, adr)


@dataclass(
    init=False, repr=True, eq=False, order=False, unsafe_hash=False, frozen=False
)
class MemoryLoad(SymbolicAnnotation):
    slot: SymbolicVariable

    def __init__(self, state, slot):
        super().__init__(state)
        self.slot = slot

    @classmethod
    def from_statespace(cls, state: GlobalState):
        op, _, _, stack, _, _ = decompose_inst(state, "MLOAD")
        adr = SymbolicVariable(stack[-1])
        return cls(state, adr)


@dataclass(
    init=False, repr=True, eq=False, order=False, unsafe_hash=False, frozen=False
)
class StorageWrite(SymbolicAnnotation):
    slot: SymbolicVariable
    value: SymbolicVariable

    def __init__(
        self,
        state,
        slot,
        value,
    ):
        super().__init__(state)
        self.slot = slot
        self.value = value

    @classmethod
    def from_statespace(cls, state: GlobalState):
        op, _, _, stack, _, _ = decompose_inst(state, "SSTORE")
        adr = SymbolicVariable(stack[-1])
        val = SymbolicVariable(stack[-2])
        return cls(state, adr, val)


dataclass(init=False, repr=True, eq=False, order=False, unsafe_hash=False, frozen=False)


class MemoryWrite(SymbolicAnnotation):
    slot: SymbolicVariable
    value: SymbolicVariable

    def __init__(
        self,
        state,
        slot,
        value,
    ):
        super().__init__(state)
        self.slot = slot
        self.value = value

    @classmethod
    def from_statespace(cls, state: GlobalState):
        op, _, _, stack, _, _ = decompose_inst(state, "MSTORE")
        adr = SymbolicVariable(stack[-1])
        val = SymbolicVariable(stack[-2])
        return cls(state, adr, val)


@dataclass(
    init=False, repr=True, eq=False, order=False, unsafe_hash=False, frozen=False
)
class Log(SymbolicAnnotation):

    n: int
    topic0: SymbolicVariable
    topic1: SymbolicVariable
    topic2: SymbolicVariable
    topic3: SymbolicVariable
    data: SymbolicMemorySlice

    def __init__(self, state, n, topic0, topic1, topic2, topic3, data):
        super().__init__(state)
        self.n = n
        self.topic0 = topic0
        self.topic1 = topic1
        self.topic2 = topic2
        self.topic3 = topic3
        self.data = data

    def try_get_selector(self):
        val = self.topic0.concrete_val()
        return hex(val) if val is not None else None

    @classmethod
    def from_statespace(cls, state: GlobalState):
        LOG_TO_N = {"LOG0": 0, "LOG1": 1, "LOG2": 2, "LOG3": 3, "LOG4": 4}
        op, _, _, stack, _, _ = decompose_inst(state)

        if "LOG" not in op:
            raise Exception("{} is not a LOG instruction".format(op))

        n = LOG_TO_N[op]
        topic0 = None
        topic1 = None
        topic2 = None
        topic3 = None

        if n == 0:
            size, mem_start = stack[-2:]
        elif n == 1:
            topic0, size, mem_start = stack[-3:]
        elif n == 2:
            topic1, topic0, size, mem_start = stack[-4:]
        elif n == 3:
            topic2, topic1, topic0, size, mem_start = stack[-5:]
        elif n == 4:
            topic3, topic2, topic1, topic0, size, mem_start = stack[-6:]

        data = decode_memory(state, SymbolicVariable(mem_start), SymbolicVariable(size))

        return cls(
            state,
            n,
            SymbolicVariable(topic0) if topic0 else None,
            SymbolicVariable(topic1) if topic1 else None,
            SymbolicVariable(topic2) if topic2 else None,
            SymbolicVariable(topic3) if topic3 else None,
            data,
        )


@dataclass(
    init=False, repr=True, eq=False, order=False, unsafe_hash=False, frozen=False
)
class Return(SymbolicAnnotation):
    data: SymbolicMemorySlice

    def __init__(self, state, data):
        super().__init__(state)
        self.data = data

    @classmethod
    def from_statespace(cls, state: GlobalState):
        op, _, _, stack, _, _ = decompose_inst(state, "RETURN")
        size, mem_start = state.mstate.stack[-2:]
        return cls(
            state,
            decode_memory(state, SymbolicVariable(mem_start), SymbolicVariable(size)),
        )


@dataclass(
    init=False, repr=True, eq=False, order=False, unsafe_hash=False, frozen=False
)
class Revert(SymbolicAnnotation):
    data: SymbolicMemorySlice

    def __init__(self, state, data):
        super().__init__(state)
        self.data = data

    @classmethod
    def from_statespace(cls, state: GlobalState):
        op, _, _, stack, _, _ = decompose_inst(state, "REVERT")
        size, mem_start = state.mstate.stack[-2:]
        return cls(
            state,
            decode_memory(state, SymbolicVariable(mem_start), SymbolicVariable(size)),
        )


@dataclass(
    init=False, repr=True, eq=False, order=False, unsafe_hash=False, frozen=False
)
class Selfdestruct(SymbolicAnnotation):
    address: SymbolicVariable

    def __init__(self, state, address):
        super().__init__(state)
        self.address = address

    @classmethod
    def from_statespace(cls, state: GlobalState):
        op, _, _, stack, _, _ = decompose_inst(state, "SELFDESTRUCT")
        adr = stack[-1]
        return cls(
            state,
            SymbolicVariable(adr),
        )


@dataclass(
    init=False, repr=True, eq=False, order=False, unsafe_hash=False, frozen=False
)
class UnconditionalJump(SymbolicAnnotation):
    to: SymbolicVariable

    def target_int(self) -> Optional[int]:
        return self.to.concrete_val()

    def __init__(self, state, to):
        super().__init__(state)
        self.to = to

    @classmethod
    def from_statespace(cls, state: GlobalState):
        op, _, _, stack, _, _ = decompose_inst(state, "JUMP")
        to = stack[-1]
        return cls(
            state,
            SymbolicVariable(to),
        )


@dataclass(
    init=False, repr=True, eq=False, order=False, unsafe_hash=False, frozen=False
)
class ConditionalJump(SymbolicAnnotation):
    to: SymbolicVariable
    condition: object

    def target_int(self) -> Optional[int]:
        return self.to.concrete_val()

    def __init__(self, state, to, condition):
        super().__init__(state)
        self.to = to
        self.condition = condition

    @classmethod
    def from_statespace(cls, state: GlobalState):
        op, _, _, stack, _, _ = decompose_inst(state, "JUMPI")
        to = stack[-1]
        jmp_condition = stack[-2]
        return cls(state, SymbolicVariable(to), SymbolicVariable(jmp_condition))


@dataclass(
    init=False, repr=True, eq=False, order=False, unsafe_hash=False, frozen=False
)
class Calldataload(SymbolicAnnotation):
    offset: SymbolicVariable

    def __init__(self, state, offset):
        super().__init__(state)
        self.offset = offset

    @classmethod
    def from_statespace(cls, state: GlobalState):
        op, pc, instruction, stack, _, _ = decompose_inst(state, "CALLDATALOAD")
        offset = state.mstate.stack[-1]
        return cls(state, SymbolicVariable(offset))


@dataclass(
    init=False, repr=True, eq=False, order=False, unsafe_hash=False, frozen=False
)
class Calldatacopy(SymbolicAnnotation):
    offset: SymbolicVariable
    mem_addr: SymbolicVariable
    length: SymbolicVariable

    def __init__(self, state, offset, mem_addr, length):
        super().__init__(state)
        self.offset = offset
        self.mem_addr = mem_addr
        self.length = length

    @classmethod
    def from_statespace(cls, state: GlobalState):
        op, pc, instruction, stack, _, _ = decompose_inst(state, "CALLDATACOPY")
        offset, mem_addr, length = state.mstate.stack[-3:]
        return cls(
            state,
            SymbolicVariable(offset),
            SymbolicVariable(mem_addr),
            SymbolicVariable(length),
        )


@dataclass(
    init=False, repr=True, eq=False, order=False, unsafe_hash=False, frozen=False
)
class Create(SymbolicAnnotation):
    value: SymbolicVariable
    data: SymbolicMemorySlice

    def __init__(self, state, value, data):
        super().__init__(state)
        self.value = value
        self.data = data

    @classmethod
    def from_statespace(cls, state: GlobalState):
        op, pc, instruction, stack, _, _ = decompose_inst(state, "CREATE")
        length, mem_addr, value = state.mstate.stack[-3:]
        return cls(
            state,
            SymbolicVariable(value),
            decode_memory(state, SymbolicVariable(mem_addr), SymbolicVariable(length)),
        )


@dataclass(
    init=False, repr=True, eq=False, order=False, unsafe_hash=False, frozen=False
)
class Create2(SymbolicAnnotation):
    salt: SymbolicVariable
    value: SymbolicVariable
    data: SymbolicMemorySlice

    def __init__(self, state, salt, value, data):
        super().__init__(state)
        self.salt = salt
        self.value = value
        self.data = data

    @classmethod
    def from_statespace(cls, state: GlobalState):
        op, pc, instruction, stack, _, _ = decompose_inst(state, "CREATE2")
        salt, length, mem_addr, value = state.mstate.stack[-4:]
        return cls(
            state,
            SymbolicVariable(salt),
            SymbolicVariable(value),
            decode_memory(state, SymbolicVariable(mem_addr), SymbolicVariable(length)),
        )


@dataclass(
    init=False, repr=True, eq=False, order=False, unsafe_hash=False, frozen=False
)
class SenderConstraintFunction(SymbolicAnnotation):
    address: SymbolicVariable
    condition: SymbolicExpression
    is_storage_address: bool = True
    is_probably_mapping: bool = False
    true_branch_reachable: bool = False
    false_branch_reachable: bool = False
    model: object

    def __init__(
        self,
        state,
        address,
        condition,
        model,
        true_branch_reachable=None,
        false_branch_reachable=None,
        is_storage_address=True,
        probably_mapping=False,
    ):
        super().__init__(state)
        self.address = address
        self.condition = condition
        self.true_branch_reachable = true_branch_reachable
        self.false_branch_reachable = false_branch_reachable
        self.is_storage_address = is_storage_address
        self.is_probably_mapping = probably_mapping
        self.model = model

    # To Remove duplicated constraints we change the behavior here
    def __hash__(self):
        return hash(repr(self))

    # To Remove duplicated constraints we change the behavior here
    def __eq__(self, other):
        return repr(self) == repr(other)

    @classmethod
    def from_statespace(
        cls,
        state: GlobalState,
        address,
        condition,
        model,
        true_branch_reachable=None,
        false_branch_reachable=None,
        is_storage_address=True,
        probably_mapping=False,
    ):
        op, _, _, stack, _, _ = decompose_inst(state, "JUMPI")
        return cls(
            state,
            SymbolicVariable(address),
            SymbolicExpression(condition),
            model=model,
            true_branch_reachable=true_branch_reachable,
            false_branch_reachable=false_branch_reachable,
            is_storage_address=is_storage_address,
            probably_mapping=probably_mapping,
        )


@dataclass(
    init=False, repr=True, eq=False, order=False, unsafe_hash=False, frozen=False
)
class FunctionSummary(AnnotationBase):
    name: str
    pcs: set[int] = field(default_factory=set, repr=False)
    is_payable: bool = False
    has_writes: bool = False
    has_reads: bool = False
    has_logs: bool = False
    has_calls: bool = False
    has_delegate: bool = False
    has_creates: bool = False
    has_create2s: bool = False
    has_selfdestructs: bool = False

    def __init__(self, name):
        super().__init__()
        self.name = name
        self.pcs = set()
        self.has_writes = False
        self.has_reads = False
        self.has_logs = False
        self.has_calls = False
        self.has_delegate = False
        self.has_creates = False
        self.has_create2s = False
        self.has_selfdestructs = False

    def valid_at(self, pc):
        return pc in self.pcs

    def functions(self):
        return self.name.split(" or ")

    def functions_string(self):
        return self.name

    def update(self, state: GlobalState):
        op, pc, instruction, stack, _, _ = decompose_inst(state)

        self.pcs |= {pc}

        if op == "SLOAD":
            self.has_reads = True

        if op == "SSTORE":
            self.has_writes = True

        if "LOG" in op:
            self.has_logs = True

        if op in CALL_INSTRUCTION_LIST:
            self.has_calls = True

        if op in ["DELEGATECALL", "CALLCODE"]:
            self.has_delegate = True

        if op in ["SELFDESTRUCT"]:
            self.has_selfdestructs = True

        if op in ["CREATE"]:
            self.has_creates = True

        if op in ["CREATE2"]:
            self.has_create2s = True


@dataclass(init=False, eq=False, order=False, unsafe_hash=False)
class ConstantSummary(AnnotationBase):
    length: int
    value: int
    introduced_at: set[int]

    def __init__(self, length, value, introduced_at):
        super().__init__()
        self.length, self.value, self.introduced_at = (length, value, introduced_at)

    def valid_at(self, pc):
        return pc in self.introduced_at

    def hex_value(self, leading0x=True) -> str:
        return (
            "{0:#0{1}x}".format(self.value, self.length + 2)
            if leading0x
            else "{0:0{1}x}".format(self.value, (self.length * 2))
        )

    def add_introduced_at(self, pc):
        self.introduced_at |= {pc}

    def __repr__(self):
        return "{}({})".format(
            type(self).__name__,
            ", ".join(
                [
                    "length={}".format(self.length),
                    "value={}".format(self.hex_value()),
                    "tags={}".format(self.tags),
                    "#introduced={}".format(len(self.introduced_at)),
                ]
            ),
        )


@dataclass(init=False, eq=False, order=False, unsafe_hash=False)
class AssemblySummary(AnnotationBase):
    constants: list[ConstantSummary]
    function_entrypoints: list[FunctionEntrypoint]
    jump_targets: list[JumpTarget]
    jumps: set[int]
    jumpdests: set[int]
    meta_data: MetaDataString
    unique_instructions_visited: int
    total_instructions: int

    def __init__(
        self,
        constants,
        function_entrypoints,
        jump_targets,
        jumps,
        jumpdests,
        meta_data,
        unique_instructions_visited,
        total_instructions,
    ):
        super().__init__()
        (
            self.constants,
            self.function_entrypoints,
            self.jump_targets,
            self.jumps,
            self.jumpdests,
            self.meta_data,
            self.unique_instructions_visited,
            self.total_instructions,
        ) = (
            constants,
            function_entrypoints,
            jump_targets,
            jumps,
            jumpdests,
            meta_data,
            unique_instructions_visited,
            total_instructions,
        )

    def get_annotations_valid_at(self, pc):
        return (
            [x for x in self.constants if x.valid_at(pc)]
            + [x for x in self.function_entrypoints if x.valid_at(pc)]
            + [x for x in self.jump_targets if x.valid_at(pc)]
            + ([self.meta_data] if self.meta_data.valid_at(pc) else [])
        )


@dataclass(eq=False, order=False, unsafe_hash=False)
class SymbolicExecSummary:
    functions: list[FunctionSummary]
    calls: list[Call]
    storage_reads: list[StorageLoad]
    storage_writes: list[StorageWrite]
    memory_reads: list[MemoryLoad]
    memory_writes: list[MemoryWrite]
    logs: list[Log]
    returns: list[Return]
    reverts: list[Revert]
    calldataloads: list[Calldataload]
    calldatacopies: list[Calldatacopy]
    selfdestructs: list[Selfdestruct]
    conditional_jumps: list[ConditionalJump]
    unconditional_jumps: list[UnconditionalJump]
    pushes: list[Push]
    creates: list[Push]
    create2s: list[Push]
    sender_constraint_functions: list[SenderConstraintFunction]
    unique_instructions_visited: int

    def get_annotations_valid_at(self, pc):
        return (
            [x for x in self.functions if x.valid_at(pc)]
            + [x for x in self.calls if x.valid_at(pc)]
            + [x for x in self.storage_reads if x.valid_at(pc)]
            + [x for x in self.storage_writes if x.valid_at(pc)]
            + [x for x in self.memory_reads if x.valid_at(pc)]
            + [x for x in self.memory_writes if x.valid_at(pc)]
            + [x for x in self.logs if x.valid_at(pc)]
            + [x for x in self.returns if x.valid_at(pc)]
            + [x for x in self.reverts if x.valid_at(pc)]
            + [x for x in self.calldataloads if x.valid_at(pc)]
            + [x for x in self.calldatacopies if x.valid_at(pc)]
            + [x for x in self.conditional_jumps if x.valid_at(pc)]
            + [x for x in self.unconditional_jumps if x.valid_at(pc)]
            + [x for x in self.sender_constraint_functions if x.valid_at(pc)]
            + [x for x in self.pushes if x.valid_at(pc)]
            + [x for x in self.creates if x.valid_at(pc)]
            + [x for x in self.create2s if x.valid_at(pc)]
        )
