from functools import lru_cache
from ethpector.classify import (
    InterfaceMatch,
    ContractClassifier,
    KnownBytecode,
    KnownAddress,
)
from ethpector.data import (
    FunctionEntrypoint,
    AssemblySummary,
    ConstantSummary,
    JumpTarget,
)
from .program import Program, BasicBlocks
from .flow import ReachingDefState


class AssemblyAnalyzer:
    def __init__(self, code, online_resolver, config):
        self.online_resolver = online_resolver
        self.config = config
        self.program = Program(
            code, strip_metadata=config.drop_metadata_string_before_analysis()
        )
        self.classifier = ContractClassifier()
        bb = self.program.get_basic_blocks()
        if len(bb) > 0:
            inital_state = ReachingDefState(self.program, bb[0])
            inital_state.execute()
        self.bbs = bb

    @lru_cache(maxsize=1)
    def get_constants(self):
        pushes = {}
        for inst in self.program.get_constants():
            if inst.operand_size() not in pushes:
                pushes[inst.operand_size()] = {}
            hexop = inst.operand().to_bytes(inst.operand_size(), byteorder="big").hex()
            if hexop not in pushes[inst.operand_size()]:
                pushes[inst.operand_size()][hexop] = set()

            pushes[inst.operand_size()][hexop] |= {inst.pc()}
        return [
            ConstantSummary(length=length, value=int(value, 16), introduced_at=pcs)
            for length, cvd in pushes.items()
            for value, pcs in cvd.items()
        ]

    @lru_cache(maxsize=1)
    def get_code_hash(self):
        return self.program.get_code_hash()

    def annotate_constants(self, constants):
        lookup = self.online_resolver
        addr_mask = int("0xffffffffffffffffffffffffffffffffffffffff", 16)

        for const in constants:
            constant_length = const.length
            r = None
            if constant_length == 4:
                r = lookup.function_name(const.hex_value(leading0x=False))
            elif constant_length == 32:
                r = lookup.event_name(const.hex_value(leading0x=False))
            elif constant_length == 20:
                if const.value != addr_mask:
                    r = lookup.account_summary(const.hex_value())
            if r:
                const.set_tag("address_summary", r)

            jumpdests = self.program.get_jumpdest_positions()
            if const.value in jumpdests:
                const.set_tag("is_jump_dest", True)

        return constants

    @lru_cache(maxsize=1)
    def get_basic_blocks(self) -> BasicBlocks:
        return self.bbs

    @lru_cache(maxsize=1)
    def get_program(self) -> Program:
        return self.program

    @lru_cache(maxsize=1)
    def get_calls(self):
        return self.program.get_calls()

    @lru_cache(maxsize=1)
    def get_storage_reads(self):
        return self.program.get_storage_reads()

    @lru_cache(maxsize=1)
    def get_storage_writes(self):
        return self.program.get_storage_writes()

    @lru_cache(maxsize=1)
    def get_function_entrypoints(self):
        return [
            FunctionEntrypoint(pc=p, function_name=n)
            for n, p in self.program.get_functions(
                online_lookup=not self.config.offline()
            )
        ]

    def get_interface_matches(self, threshold=0.5) -> list[InterfaceMatch]:
        c = self.get_constants()
        functions = [y for x in self.get_function_entrypoints() for y in x.functions()]
        events = [x.hex_value() for x in c if x.length == 32]
        constants = [x.hex_value() for x in c]

        return self.classifier.get_interface_matches(
            functions=functions, events=events, constants=constants, threshold=threshold
        )

    def get_bytecode_matches(self) -> list[KnownBytecode]:
        return self.classifier.find_known_bytecode(self.program.get_full_bytecode())

    def get_known_contracts(self, address) -> list[KnownAddress]:
        return self.classifier.find_known_contracts(address)

    @lru_cache(maxsize=1)
    def get_summary(self) -> AssemblySummary:
        constants = self.annotate_constants(self.get_constants())

        return AssemblySummary(
            constants=constants,
            function_entrypoints=self.get_function_entrypoints(),
            jump_targets=[
                JumpTarget(pc, value)
                for pc, value in self.program.get_jump_targets().items()
            ],
            jumps=self.program.get_jump_positions(),
            jumpdests=self.program.get_jumpdest_positions(),
            meta_data=self.program.get_metadata_annotation(),
            unique_instructions_visited=len(self.program.get_reachable_pcs()),
            total_instructions=len(self.program.get_instructions()),
        )
