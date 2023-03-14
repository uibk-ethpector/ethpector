import logging
import copy
from .program import Program, BasicBlock

log = logging.getLogger(__name__)


class Stack:
    def __init__(self):
        self._data = []

    def __hash__(self):
        return hash(tuple(self._data))

    def clear(self):
        self._data = []

    def pop(self):
        return self._data.pop()

    def popn(self, n):
        return [self.pop() for _ in range(0, n)]

    def peekn(self, n):
        return [self._data[-i] for i in range(1, n + 1)]

    def peek(self):
        return self._data[-1]

    def push(self, v):
        self._data.append(v)

    def dup(self, n):
        assert n != 0
        self._data.append(self._data[-n])

    def swap(self, n):
        assert n != 0
        self._data[-(n + 1)], self._data[-1] = self._data[-1], self._data[-(n + 1)]

    def len(self):
        return len(self._data)

    def list(self):
        return self._data

    def __str__(self):
        return str(self._data)

    def __repr__(self):
        return str(self)


class EvmState:
    def ident(self) -> str:
        pass

    def advance(self) -> set[object]:
        pass

    def execute(self, threshold=10**5):
        stack = Stack()
        stack.push(self)
        seen = {}
        counter = 0

        while stack.len() > 0 and counter < threshold:
            log.debug(
                "Abstract interpretation: " f"Main Loop {stack.len()} items to process"
            )
            state = stack.pop()

            try:
                new_states = state.advance()
            except Exception as e:
                log.error(f"There was an error exploring the execution state. {e}")
                new_states = []

            counter += 1
            log.debug(
                "Abstract interpretation: "
                f"Got new states {len(new_states)} {stack.len()}"
            )
            for ns in new_states:
                if not ns.ident() in seen:
                    stack.push(ns)
                    seen[ns.ident()] = True

        if counter >= threshold:
            log.error(
                f"More than {threshold} states processed - giving up. "
                "This is probably a bug in the data-flow analysis"
            )


class ReachDef:
    reaches: list

    def __init__(self, height):
        self.reaches = [set() for _ in range(0, height, 1)]

    def len(self):
        return len(self.reaches)

    def __str__(self):
        f_sets = ",".join(
            ["{" + " | ".join([str(x) for x in s]) + "}" for s in self.reaches]
        )
        return f"reaches=[{f_sets}]"

    def __repr__(self):
        return str(self)


class ReachingDefState(EvmState):
    def __init__(self, p: Program, bb: BasicBlock, stack: Stack = Stack()):
        self.bb = bb
        self.stack = stack
        self.program = p

    def update_block_reachings(self):
        ann = self.bb.get_single_annotation(ReachDef)
        if ann is None:
            ann = ReachDef(self.stack.len())
            self.bb.add_annotation(ann)

        cs = copy.deepcopy(self.stack)
        for i in range(0, self.stack.len()):
            if ann.len() <= i:
                break

            ann.reaches[i] |= {cs.pop()}

        if self.stack.len() < len(ann.reaches):
            ann.reaches = ann.reaches[: self.stack.len()]

    def update_instruction_reachings(self, inst, pcs):
        ann = inst.get_single_annotation(ReachDef)
        if ann is None:
            ann = ReachDef(len(pcs))
            inst.add_annotation(ann)

        for i, v in enumerate(pcs):
            ann.reaches[i] |= {v}

    def ident(self):
        return (self.bb.index(), hash(self.stack))

    def get_target_basic_block(self, jump_pc, push_pc):
        # t = None
        # if jump_pc in self.jump_targets:
        #     t = self.jump_targets[jump_pc]
        # else:
        t = None
        inst = self.program.get_instruction_by_pc(push_pc)
        if inst.is_push():
            t = inst.operand()
            # self.program.jump_targets[jump_pc] = inst.operand()
        elif inst.name() == "AND":
            # resolve simple masking
            ann = inst.get_single_annotation(ReachDef)
            if ann is not None and len(ann.reaches) == 2:
                ann_inst = [
                    self.program.get_instruction_by_pc(list(s)[0])
                    for s in ann.reaches
                    if len(s) == 1
                ]
                mask = [x for x in ann_inst if x.is_mask()]
                value = [x for x in ann_inst if not x.is_mask()]
                if len(mask) == 1 and len(value) == 1:
                    t = value[0].operand()

        if t:
            self.program.jump_targets[jump_pc] = t
            return self.program.get_basic_block_by_pc(t)
        else:
            log.error(
                "Could not find jump target for instruction at "
                f"pc {jump_pc}, creating instruction is {inst}"
            )
            return None

    def advance(self) -> set[EvmState]:
        log.debug(f"Processing Block: {self.ident()}")

        self.update_block_reachings()

        stack = copy.deepcopy(self.stack)
        for inst in self.bb.get_instructions():
            log.debug(f"Processing instruction: {self.ident()}, {inst} {stack}")

            self.program.mark_reachable(inst.pc)

            if inst.is_dup() or inst.is_swap():
                # for swaps and dups dont pop
                stack_reads = stack.peekn(inst.pops())
            else:
                stack_reads = stack.popn(inst.pops())

            self.update_instruction_reachings(inst, stack_reads)

            if inst.is_endtx():
                # terminates transaction no new states.
                return []
            elif inst.is_push():
                stack.push(inst.pc())
            elif inst.is_dup():
                stack.dup(inst.pops())
            elif inst.is_swap():
                stack.swap(inst.pops() - 1)
            elif inst.name() == "JUMP":
                target = self.get_target_basic_block(inst.pc(), stack_reads[0])
                return (
                    [ReachingDefState(self.program, target, copy.deepcopy(stack))]
                    if target
                    else []
                )
            elif inst.name() == "JUMPI":
                ret = []
                target = self.get_target_basic_block(inst.pc(), stack_reads[0])
                if target:
                    ret.append(
                        ReachingDefState(self.program, target, copy.deepcopy(stack))
                    )

                if self.bb.nextBlockIndex is not None:
                    nextBlock = self.program.get_basic_block_by_index(
                        self.bb.nextBlockIndex
                    )
                    ret.append(
                        ReachingDefState(self.program, nextBlock, copy.deepcopy(stack))
                    )
                return ret
            else:
                if inst.pushes() == 1:
                    stack.push(inst.pc())
                elif inst.pushes() > 1:
                    raise Exception(f"no such instruction should exist, {inst}")

            if stack.len() > 1024:
                log.error("Stack to deep, contract might be recursive. Aborting.")
                return []

        # the case of fall through blocks without jumps in the end
        if self.bb.nextBlockIndex is not None:
            nextBlock = self.program.get_basic_block_by_index(self.bb.nextBlockIndex)
            return [ReachingDefState(self.program, nextBlock, stack)]

        return []
