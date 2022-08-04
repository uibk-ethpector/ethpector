import logging
import pyevmasm as EVMAsm
import networkx as nx
from typing import Optional, Tuple
from mythril.ethereum import util
from mythril.support.support_utils import get_code_hash
from mythril.disassembler.disassembly import Disassembly
from ethpector.data import (
    ToJsonDecorator,
    AnnotationBase,
    MetaDataString,
    JumpTarget,
    ConditionalJump,
    UnconditionalJump,
    CALL_INSTRUCTION_LIST,
)
from ethpector.utils import pairwise, is_max_int
from .metadata import BinaryMetadata

log = logging.getLogger(__name__)


@ToJsonDecorator
class Instruction:
    instruction: EVMAsm.Instruction
    annotations: list[AnnotationBase]

    def __init__(self, instruction):
        self.instruction = instruction
        self.annotations = []

    def raw(self) -> EVMAsm.Instruction:
        return self.instruction

    def pc(self) -> int:
        return self.instruction.pc

    def name(self) -> int:
        return self.instruction.name

    def operand(self) -> int:
        return self.instruction.operand

    def pops(self) -> int:
        return self.instruction.pops

    def pushes(self) -> int:
        return self.instruction.pushes

    def is_endtx(self) -> bool:
        return self.instruction.is_endtx

    def is_dup(self) -> bool:
        return self.instruction.name.startswith("DUP")

    def is_jumpi(self) -> bool:
        return self.instruction.name == "JUMPI"

    def is_jump(self) -> bool:
        return self.instruction.name == "JUMP"

    def is_push(self) -> bool:
        return self.instruction.name.startswith("PUSH")

    def is_swap(self) -> bool:
        return self.instruction.name.startswith("SWAP")

    def operand_hex(self) -> str:
        return (
            "0x" + self.operand().to_bytes(self.operand_size(), byteorder="big").hex()
        )

    def operand_size(self) -> int:
        return self.instruction.operand_size

    def has_operand(self) -> bool:
        return self.instruction.has_operand

    def is_mask(self) -> bool:
        return self.has_operand() and is_max_int(self.operand(), self.operand_size())

    def is_terminator(self) -> bool:
        return self.instruction.is_terminator

    def is_branch(self):
        return self.instruction.is_branch

    def get_annotations(self, filter_type):
        return [x for x in self.annotations if type(x) == filter_type]

    def add_annotation(self, ann):
        self.annotations.append(ann)

    def get_single_annotation(self, filter_type):
        ann = self.get_annotations(filter_type)
        if len(ann) == 0:
            return None
        elif len(ann) == 1:
            return ann[0]
        else:
            raise Exception("Too many annotations")

    def __str__(self):
        operand = self.instruction.operand if self.instruction.has_operand else None

        if operand is not None and self.instruction.operand_size <= 4:
            operand = hex(operand) + f"({operand})"
        elif operand is not None:
            operand = hex(operand)

        inst = "{pc:>6}({pcd:>6}): {inst:<12} {par:>64}".format(
            pc=hex(self.instruction.pc),
            pcd=self.instruction.pc,
            inst=str(self.instruction.name),
            par=operand if operand else "",
        )
        return "{} # {}".format(inst, self.annotations)

    def __repr__(self):
        return repr(self.instruction)


@ToJsonDecorator
class BasicBlock:
    i: int
    instructions: list[Instruction]
    annotations: list[AnnotationBase]
    nextBlockIndex: Optional[int]

    def index(self):
        return self.i

    def __init__(self, i):
        self.i = i
        self.instructions = []
        self.annotations = []
        self.nextBlockIndex = None

    def __repr__(self):
        return self.__str__()

    def get_instructions(self):
        return self.instructions

    def get_last_instruction(self):
        if not any(self.instructions):
            return None
        else:
            return self.instructions[-1]

    def get_first_pc(self):
        return self.instructions[0].pc() if len(self.instructions) > 0 else None

    def add_annotation(self, ann):
        self.annotations.append(ann)

    def get_annotations(self, filter_type):
        return [x for x in self.annotations if type(x) == filter_type]

    def get_single_annotation(self, filter_type):
        ann = self.get_annotations(filter_type)
        if len(ann) == 0:
            return None
        elif len(ann) == 1:
            return ann[0]
        else:
            raise Exception("Too many annotations")

    def is_static_jump_block(self) -> bool:
        li = self.get_last_instruction()
        if li is None:
            return False
        else:
            return li.is_jump()

    def is_terminator_block(self) -> bool:
        li = self.get_last_instruction()
        if li is None:
            return True
        else:
            return self.instructions[-1].is_terminator()

    def get_next_block_true_branch(self) -> Optional[int]:
        li = self.get_last_instruction()
        if li is not None:
            if li.is_jump():
                ann = li.get_single_annotation(JumpTarget)
                if ann is not None:
                    return ann.target_int()
                ann = li.get_single_annotation(UnconditionalJump)
                if ann is not None:
                    return ann.target_int()
                log.warning("Did not find true branch target for unconditional branch.")
            elif li.is_jumpi():
                ann = li.get_single_annotation(ConditionalJump)
                if ann is not None:
                    return ann.target_int()
                ann = li.get_single_annotation(JumpTarget)
                if ann is not None:
                    return ann.target_int()
                log.warning("Did not find true branch target conditional branch.")

        return None

    def get_next_block_false_branch(self):
        li = self.get_last_instruction()
        if li is not None:
            if li.is_jumpi():
                return self.nextBlockIndex
        return None

    def propagage_block_annotations(self):
        intersection = list(
            set.intersection(*[set(x.annotations) for x in self.instructions])
        )
        self.annotations += intersection

        for inst in self.instructions:
            for r in intersection:
                inst.annotations.remove(r)

    def __str__(self):
        spacer = "#" * 80
        return "\n{}\nBlock {}\n{}\n{}".format(spacer, self.i, self.annotations, spacer)


@ToJsonDecorator
class BasicBlocks(list):
    def get_cfg(self):
        g = nx.DiGraph()
        for i, x in enumerate(self):
            g.add_node(i)
            tb = x.get_next_block_true_branch()
            if tb is not None:
                g.add_edge(i, tb, is_true_branch=True)
            fb = x.get_next_block_false_branch()
            if fb is not None:
                g.add_edge(i, fb, is_true_branch=False)
        return g


class Program:
    def __init__(self, hex_code, strip_metadata=False):
        self.meta = BinaryMetadata(hex_code)
        self.code_to_analyze = (
            self.meta.code_without_metadata() if strip_metadata else hex_code
        )
        self.code = hex_code
        self.instructions = [
            Instruction(x)
            for x in EVMAsm.disassemble_all(util.safe_decode(self.code_to_analyze))
        ]
        self.pc_to_inst = {inst.pc(): inst for inst in self.instructions}
        self.jump_targets = self._create_simple_jump_targets()
        self.basic_blocks = self._create_basic_blocks()
        self.pc_to_block = {bb.get_first_pc(): bb for bb in self.basic_blocks}
        self.index_to_block = {bb.index(): bb for bb in self.basic_blocks}
        self.reachable_pcs = set()

    def __hash__(self):
        return hash(self.code)

    def _create_simple_jump_targets(self) -> dict:
        last_inst = None
        targets = {}
        for inst in self.instructions:
            if last_inst and inst.is_branch() and last_inst.has_operand():
                targets[inst.pc()] = last_inst.operand()

            last_inst = inst
        return targets

    def _create_basic_blocks_raw(self):
        i = 0
        blocks = {}
        just_ended_bb = False
        for inst in self.instructions:
            if inst.name() == "JUMPDEST" and not just_ended_bb:
                i += 1

            just_ended_bb = False
            if i not in blocks:
                blocks[i] = []
            blocks[i].append(inst)

            if inst.is_terminator():
                i += 1
                just_ended_bb = True
        return blocks

    def _create_basic_blocks(self) -> BasicBlocks:
        bbs = self._create_basic_blocks_raw()
        blocks_out = BasicBlocks()
        for i, block in bbs.items():
            bb = BasicBlock(i)
            for inst in block:
                bb.instructions.append(inst)

            blocks_out.append(bb)

        for b, nb in pairwise(blocks_out):
            if nb:
                b.nextBlockIndex = nb.index()

        return blocks_out

    def get_basic_block_by_pc(self, pc):
        if pc not in self.pc_to_block:
            log.error(
                f"There is no basic block start at pc {pc}. " "Invalid jump location"
            )
            return None
        return self.pc_to_block[pc]

    def get_functions(self, online_lookup: bool) -> list[Tuple[int, str]]:
        myth_diss = Disassembly(
            self.get_bytecode_to_analyze(),
            enable_online_lookup=online_lookup,
        )
        return myth_diss.function_name_to_address.items()

    def mark_reachable(self, pc):
        self.reachable_pcs.add(pc)

    def get_reachable_pcs(self):
        return self.reachable_pcs

    def get_basic_block_by_index(self, index):
        return self.index_to_block[index]

    def get_basic_blocks(self) -> dict:
        return self.basic_blocks

    def get_jump_targets(self) -> dict:
        return self.jump_targets

    def get_instruction_by_pc(self, pc):
        if pc in self.pc_to_inst:
            return self.pc_to_inst[pc]
        else:
            return None

    def get_instructions(self) -> list[Instruction]:
        return self.instructions

    def get_code_hash(self) -> str:
        return get_code_hash(self.code)

    def get_metadata_annotation(self) -> MetaDataString:
        return MetaDataString(
            raw=self.meta.meta_obj(),
            index=self.meta.offset(),
            data=self.meta.bytes(),
            url=self.meta.url(),
        )

    def get_constants(self):
        return [x for x in self.instructions if x.has_operand()]

    def get_full_bytecode(self) -> str:
        return self.code

    def get_bytecode_to_analyze(self) -> str:
        return self.code_to_analyze

    def get_jump_positions(self) -> set[int]:
        return {inst.pc() for inst in self.instructions if inst.is_branch()}

    def get_jumpdest_positions(self) -> set[int]:
        return {inst.pc() for inst in self.instructions if inst.name() == "JUMPDEST"}

    def get_calls(self):
        return [x for x in self.instructions if x.name() in CALL_INSTRUCTION_LIST]

    def get_storage_reads(self):
        return [x for x in self.instructions if x.name() in "SLOAD"]

    def get_storage_writes(self):
        return [x for x in self.instructions if x.name() in "SSTORE"]
