import pyevmasm
import re
from typing import Optional
from dataclasses import dataclass
from functools import lru_cache
from ethpector.symbolic import SymbolicAnalyzer
from ethpector.classify import InterfaceMatch, KnownBytecode, KnownAddress
from ethpector.assembly import AssemblyAnalyzer
from ethpector.config import Configuration
from ethpector.data import (
    DataProvider,
    AssemblySummary,
    AccountSummary,
    SymbolicExecSummary,
    ToJsonDecorator,
    AnnotationBase,
    AggregateProvider,
    FunctionEntrypoint,
    SenderConstraintFunction,
    FunctionSummary,
)
from .assembly.program import BasicBlocks


@ToJsonDecorator
@dataclass
class Coverage:

    """Stores the code coverage that was reached with the symbolic execution
    (symbolic) engine and the data flow analysis (assembly)
    """

    symbolic: float
    assembly: float


@ToJsonDecorator
@dataclass
class ResultSummary:

    """
    Holds the data extracted for the binary (dissassmebly) and
    via symbolic execution (symbolic) as well as the coverage reached in both.
    """

    symbolic: SymbolicExecSummary
    disassembly: AssemblySummary
    address_summary: Optional[AccountSummary]
    coverage: Coverage


@ToJsonDecorator
@dataclass
class SourceSummary:

    """
    Summarizes all source-code related information extracted by ethpector.
    """

    source_code: Optional[object]
    source_abi: Optional[object]
    source_metadata: Optional[object]

    def get_erc_mentions(self):
        j = self.to_json()
        return set(
            re.findall(
                r"erc\d+|erc-\d+|erc \d+|eip\d+|eip-\d+|eip \d+", j, re.IGNORECASE
            )
        )

    def get_contract_name(self):
        if self.source_metadata is not None and "etherscan" in self.source_metadata:
            return self.source_metadata["etherscan"]["ContractName"]
        else:
            return None


@dataclass
class ClassificationMatches:

    """
    Summarizes the potential matches of a given bytecode with known interfaces
    , byte-codes of addresses.
    """

    symbolic: list[InterfaceMatch]
    disassembly: list[InterfaceMatch]
    bytecode: list[KnownBytecode]
    address: list[KnownAddress]


@dataclass
class InstructionOverview:

    """
    Instruction and its annotation.
    """

    instruction: pyevmasm.Instruction
    detailed_overview: Optional[AnnotationBase]


@dataclass
class StorageOverview:

    """
    Reads and writes found to permanent storage found in the program.
    """

    reads: list[InstructionOverview]
    writes: list[InstructionOverview]


@dataclass
class FunctionOverview:

    """
    Summary of functions found in the program
    """

    entry_point: FunctionEntrypoint
    detailed_overview: list[FunctionSummary]
    sender_constraint: Optional[SenderConstraintFunction]


class CodeAnalysis:

    """
    The main class that aggregates all analysis functionality.

    Attributes:
        aa (AssemblyAnalyzer): Analysis based on the disassembly and simple
            dataflow.
        online_resolver (DataProvider): Abstract data provider. Is responsible
            for fetching data from online sources (node, etherscan, 4bytes etc)
        sa (SymbolicAnalyzer): Analysis capabilities based on symbolic execution
    """

    def __init__(
        self,
        address: str,
        code: str,
        config: Configuration,
        online_resolver: DataProvider,
    ):
        self.address, self.config, self.code = (address, config, code)
        self.online_resolver = (
            online_resolver if online_resolver else AggregateProvider(config)
        )
        self.aa = AssemblyAnalyzer(
            code=code, online_resolver=self.online_resolver, config=config
        )
        self.sa = SymbolicAnalyzer(
            address=address,
            code=code,
            online_resolver=self.online_resolver,
            config=config,
        )

    @lru_cache(maxsize=1)
    def get_annotated_dissassembly(self) -> BasicBlocks:
        bbs = self.aa.get_basic_blocks()
        symbolic = self.sa.get_summary()
        disassembly = self.aa.get_summary()
        for bb in bbs:
            for inst in bb.instructions:
                inst.annotations += symbolic.get_annotations_valid_at(inst.pc())
                inst.annotations += disassembly.get_annotations_valid_at(inst.pc())
            bb.propagage_block_annotations()

        return bbs

    def get_address(self):
        return self.address

    def get_online_resolver(self):
        return self.online_resolver

    @lru_cache(maxsize=1)
    def code_hash(self):
        return self.aa.get_code_hash()

    def get_bytecode(self):
        return self.code

    @lru_cache(maxsize=1)
    def get_identifier(self):
        return (
            "A-{}".format(self.address.lower())
            if self.address
            else "H-{}".format(self.code_hash())
        ).replace("0x", "")

    @lru_cache(maxsize=1)
    def get_source_summary(self):
        address, source_metadata, source_abi, source_code = (
            self.address,
            None,
            None,
            None,
        )
        if address:
            source_code = self.online_resolver.source_code(address)
            source_abi = self.online_resolver.source_abi(address)
            source_metadata = self.online_resolver.source_metadata(address)
        return SourceSummary(
            source_code=source_code,
            source_abi=source_abi,
            source_metadata=source_metadata,
        )

    @lru_cache(maxsize=1)
    def get_call_summary(self) -> list[InstructionOverview]:
        s = self.get_summary()
        ass_calls = self.aa.get_calls()
        sym_calls = {x.pc: x for x in s.symbolic.calls}

        return [
            InstructionOverview(
                instruction=x, detailed_overview=sym_calls.get(x.pc(), None)
            )
            for x in ass_calls
        ]

    @lru_cache(maxsize=1)
    def get_storage_summary(self) -> StorageOverview:
        s = self.get_summary()
        writes = self.aa.get_storage_writes()
        reads = self.aa.get_storage_reads()
        sym_reads = {x.pc: x for x in s.symbolic.storage_reads}
        sym_writes = {x.pc: x for x in s.symbolic.storage_writes}

        return StorageOverview(
            reads=[
                InstructionOverview(
                    instruction=x, detailed_overview=sym_reads.get(x.pc(), None)
                )
                for x in reads
            ],
            writes=[
                InstructionOverview(
                    instruction=x, detailed_overview=sym_writes.get(x.pc(), None)
                )
                for x in writes
            ],
        )

    @lru_cache(maxsize=1)
    def get_function_summary(self) -> FunctionOverview:
        s = self.get_summary()
        ass_f = s.disassembly.function_entrypoints
        sym_scf = {
            x.functions_string(): x for x in s.symbolic.sender_constraint_functions
        }

        return [
            FunctionOverview(
                entry_point=x,
                detailed_overview=[
                    y for y in s.symbolic.functions if y.valid_at(x.get_pc())
                ],
                sender_constraint=sym_scf.get(x.functions_string(), None),
            )
            for x in ass_f
        ]

    @lru_cache(maxsize=1)
    def get_sender_constraint_functions(self) -> FunctionOverview:
        s = self.get_summary()
        f = {y.functions_string(): y for y in s.symbolic.functions}
        ass_f = {x.functions_string(): x for x in s.disassembly.function_entrypoints}

        return [
            FunctionOverview(
                entry_point=ass_f.get(x.functions_string(), None),
                detailed_overview=f.get(x.functions_string(), None),
                sender_constraint=x,
            )
            for x in s.symbolic.sender_constraint_functions
        ]

    @lru_cache(maxsize=1)
    def get_summary(self):
        address, address_summary = (
            self.address,
            None,
        )

        if address:
            address_summary = self.online_resolver.account_summary(address)

        s = self.sa.get_summary()
        a = self.aa.get_summary()

        ac = (
            (a.unique_instructions_visited / a.total_instructions)
            if a.total_instructions > 0
            else 0
        )
        sc = (
            (s.unique_instructions_visited / a.total_instructions)
            if a.total_instructions > 0
            else 0
        )

        return ResultSummary(
            symbolic=s,
            disassembly=a,
            address_summary=address_summary,
            coverage=Coverage(symbolic=sc, assembly=ac),
        )

    @lru_cache(maxsize=1)
    def get_interface_matches(self, threshold=0.5) -> ClassificationMatches:
        return ClassificationMatches(
            symbolic=self.sa.get_interface_matches(threshold=threshold),
            disassembly=self.aa.get_interface_matches(threshold=threshold),
            bytecode=self.aa.get_bytecode_matches(),
            address=self.aa.get_known_contracts(self.address) if self.address else None,
        )
