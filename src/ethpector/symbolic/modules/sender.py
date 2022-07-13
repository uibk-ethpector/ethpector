import logging

from mythril.analysis.module.base import DetectionModule, EntryPoint
from mythril.analysis.module.module_helpers import is_prehook
from mythril.exceptions import UnsatError
from mythril.laser.ethereum.state.global_state import GlobalState
from mythril.laser.ethereum.state.annotation import StateAnnotation
from mythril.analysis.ops import get_variable
from pyevmasm import instruction_tables, DEFAULT_FORK
from ethpector.data.datatypes import SenderConstraintFunction, decompose_inst
from ethpector.utils import is_max_int, fits_in_bytes

from copy import copy

# from mythril.analysis import solver
from mythril.support.model import get_model

# from mythril.analysis.ops import VarType, Call, get_variable
# from mythril.analysis.report import Issue
# from typing import List

log = logging.getLogger(__name__)


class MsgSenderAnnotation:
    def __init__(self) -> None:
        pass


class SHAAnnotation:
    def __init__(self) -> None:
        pass


class StorageAnnotation:
    def __init__(self, address, pc) -> None:
        self.address = address
        self.pc = pc


class AddressConstantAnnotation:
    def __init__(self, address, pc) -> None:
        self.address = address
        self.pc = pc


class LOADAnnotation(StateAnnotation):
    def __init__(self, address, pc) -> None:
        self.address = address
        self.pc = pc


def get_storage_addresses_from_constraint(constraint):
    addr = set()
    name = constraint.decl().name()

    if "select" == name.lower() and len(constraint.children()) == 2:
        item, indx = constraint.children()
        if (
            item.decl().name().lower().startswith("storage")
            and indx.decl().name() == "bv"
        ):
            addr.add(indx.as_long())
    else:
        for x in constraint.children():
            addr |= get_storage_addresses_from_constraint(x)

    return addr


def based_on_msg_sender(constraint):
    ret = False
    name = constraint.decl().name()

    if name.lower().startswith("sender"):
        return True
    else:
        for x in constraint.children():
            ret = ret or based_on_msg_sender(x)

    return ret


def contains_hash(constraint):
    ret = False
    name = constraint.decl().name()

    if name.lower().startswith("keccak256_512"):
        return True
    else:
        for x in constraint.children():
            ret = ret or contains_hash(x)

    return ret


class MsgSender(DetectionModule):
    """
    This module detects whether control flow decisions are made
    based on the transaction sender.
    """

    name = "Control flow depends on msg.sender"
    # swc_id = TX_ORIGIN_USAGE
    description = "Check whether control flow decisions are influenced by msg.sender"
    entry_point = EntryPoint.CALLBACK

    def __init__(self, enable_sender_in_index):
        super().__init__()
        all_inst = [
            inst.name.replace(
                "GETPC", "PC"
            )  # pyevmasm calls the opcode GETPC and mythril PC
            for inst in instruction_tables[DEFAULT_FORK]
        ]
        self.pre_hooks = all_inst
        self.post_hooks = all_inst
        self.sender_constraint_function = []
        self.last_load_pc = None
        self.enable_sender_in_index = enable_sender_in_index

    def _execute(self, state: GlobalState) -> None:
        op, pc, instruction, stack, func, lastOp = decompose_inst(state)

        if func == "constructor" or state.environment.sender.symbolic is False:
            log.debug(
                "Looks like we are in a contract creation transaction "
                "or in a call. This module is only concerned with the "
                "code of the root contract, skipping."
            )
            return

        if is_prehook():
            self.execute_prehook(state, op, pc, instruction, stack, func, lastOp)
        else:
            self.execute_posthook(state, op, pc, instruction, stack, func, lastOp)

    def execute_posthook(
        self, state: GlobalState, op, pc, instruction, stack, func, lastOp
    ):
        if lastOp is not None and lastOp == "CALLER":
            # In CALLER posthook
            stack[-1].annotate(MsgSenderAnnotation())
        if lastOp is not None and lastOp == "SHA3":
            # In SHA3 posthook
            stack[-1].annotate(SHAAnnotation())
        elif lastOp is not None and "PUSH" in lastOp:
            # PUSH20 posthook
            if len(stack) == 0:
                log.error(
                    "Expected stack entry but there "
                    f"was none in PUSH post hook. {instruction}, after {lastOp}"
                )
            adr = stack[-1]
            adr_val = get_variable(adr)
            arg_len = int(lastOp.replace("PUSH", ""))
            if (
                arg_len > 13
                and fits_in_bytes(adr_val.val, 20)
                and not is_max_int(adr_val.val, arg_len)
            ):
                ann = AddressConstantAnnotation(adr, pc)
                stack[-1].annotate(ann)
        elif lastOp is not None and lastOp == "SLOAD":
            # In SLOAD posthook
            if self.last_load_pc is None or pc != self.last_load_pc + 1:
                log.error(
                    "ConstraintFunctions: Posthook of SLOAD should be prehook pc + 1."
                )

            ann = list(state.get_annotations(LOADAnnotation))

            for x in ann:
                if x.pc + 1 == pc:
                    stack[-1].annotate(StorageAnnotation(x.address, pc))

                    # consume annotation. Might breaks since it relies on internal
                    # properties. might use dependency annotation (DependencyAnnotation)
                    # to check for storage written.
                    if state._annotations:
                        state._annotations.remove(x)

            self.last_load_pc = None

    def execute_prehook(
        self, state: GlobalState, op, pc, instruction, stack, func, lastOp
    ):
        if op == "JUMPI":
            # We're in JUMPI prehook
            jmp_condition = stack[-2]

            # In its current form msg.sender annotations are not propagated to
            # the jmp_condition if it is part of e.g. the index of the storage
            # access. For example in patterns like require(!owners[msg.sender])
            # or require(balance[msg.sender] > 0) thats why
            # it is explicitly handled via analysis of the structure of the
            # jmp_conditions
            if (
                any(jmp_condition.get_annotations(MsgSenderAnnotation))
                or (
                    self.enable_sender_in_index
                    and based_on_msg_sender(jmp_condition.raw)
                )
            ) and any(jmp_condition.get_annotations(StorageAnnotation)):
                constraints = copy(state.world_state.constraints)
                strg = jmp_condition.get_annotations(StorageAnnotation)
                shas = jmp_condition.get_annotations(SHAAnnotation)

                addrs = get_storage_addresses_from_constraint(jmp_condition.raw)
                is_based_on_msg_sender = based_on_msg_sender(jmp_condition.raw)

                if not is_based_on_msg_sender:
                    log.error(
                        "Selected a constraint that is not based "
                        "on msg.sender. This should not happen."
                    )

                assert len(strg) >= 1

                if len(strg) > 1:
                    log.debug(
                        "Jmp condition depends on more than one storage slots, "
                        f"this is currently not supported by the this module\n {strg}"
                    )
                for i, x in enumerate(strg):
                    storage_address = get_variable(x.address).val

                    try:

                        # from mythril.laser.smt import symbol_factory
                        # from mythril.analysis.solver import pretty_print_model
                        from mythril.laser.smt import Not, Bool, simplify

                        constraints.append(
                            state.environment.active_account.storage[x.address]
                            == state.environment.sender
                        )
                        # 0xDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF

                        # False case
                        negated = (
                            simplify(Not(jmp_condition))
                            if isinstance(jmp_condition, Bool)
                            else jmp_condition == 0
                        )
                        negated.simplify()
                        # True case
                        condi = (
                            simplify(jmp_condition)
                            if isinstance(jmp_condition, Bool)
                            else jmp_condition != 0
                        )
                        condi.simplify()

                        model = None

                        # Check if TRUE part can be reached
                        # storage filed is set to the sender
                        constraints_copy = copy(constraints)
                        constraints_copy.append(condi)
                        true_reachable = constraints_copy.is_possible
                        model_true = (
                            get_model(constraints_copy) if true_reachable else None
                        )
                        # if true_part_reachable:

                        #     print(pretty_print_model(model))

                        # Check if FALSE part can be reached
                        # storage filed is set to the sender
                        constraints_copy = copy(constraints)
                        constraints_copy.append(negated)
                        false_reachable = constraints_copy.is_possible
                        model_false = (
                            get_model(constraints_copy) if false_reachable else None
                        )

                        # if false_part_reachable:
                        #     print("False Part:")
                        #     model_false = get_model(constraints_copy)
                        #     print(pretty_print_model(model))
                        jmp_str = str(jmp_condition)
                        const_str = str(constraints_copy)
                        if false_reachable and true_reachable:
                            log.error(
                                f"{func}: Both false and true part are reachable "
                                "if sender is set in storage field, does not look "
                                "like owner check. "
                                f"In jump {jmp_str} "
                                "with path constraint "
                                f" {const_str}"
                            )
                            continue
                        elif false_reachable:
                            model = model_false
                        elif true_reachable:
                            model = model_true
                        else:
                            log.error(
                                f"{func}: None of the paths are reachable if sender is "
                                "set in storage field, skipping potential "
                                "sender constraint."
                                f"In jump {jmp_str} "
                                "with path constraint "
                                f" {const_str}"
                            )
                            continue

                        if (
                            type(storage_address) == int
                            and storage_address not in addrs
                        ):
                            log.warning(
                                "Storage address is not part of the constraint. "
                                f"skipping: {jmp_condition}. "
                                f"Slot: {storage_address} not in {addrs}. Func: {func}"
                            )

                        self.sender_constraint_function.append(
                            SenderConstraintFunction.from_statespace(
                                state,
                                storage_address,
                                jmp_condition,
                                model=model,
                                true_branch_reachable=true_reachable,
                                false_branch_reachable=false_reachable,
                                probably_mapping=any(shas)
                                or (
                                    contains_hash(x.address.raw)
                                    if type(storage_address) != int
                                    else False
                                ),
                            )
                        )
                    except UnsatError:
                        return
            elif any(jmp_condition.get_annotations(MsgSenderAnnotation)) and any(
                jmp_condition.get_annotations(AddressConstantAnnotation)
            ):
                constraints = copy(state.world_state.constraints)
                strg = jmp_condition.get_annotations(AddressConstantAnnotation)
                shas = jmp_condition.get_annotations(SHAAnnotation)

                assert len(strg) >= 1

                if len(strg) > 1:
                    log.debug(
                        "Jmp condition depends on more than one address constants, "
                        f"this is currently not supported by the this module\n {strg}"
                    )

                for i, x in enumerate(strg):
                    address = get_variable(x.address).val
                    try:
                        model = get_model(constraints)
                        # solver.pretty_print_model(model)

                        self.sender_constraint_function.append(
                            SenderConstraintFunction.from_statespace(
                                state,
                                address,
                                jmp_condition,
                                is_storage_address=False,
                                probably_mapping=any(shas),
                                model=model,
                            )
                        )
                    except UnsatError:
                        return

        elif op == "SLOAD":
            # SLOAD prehook
            adr = stack[-1]
            state.annotate(LOADAnnotation(adr, pc))
            self.last_load_pc = pc
