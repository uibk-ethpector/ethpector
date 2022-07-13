import re
import eth_abi
from dataclasses import dataclass
from pypeg2 import (
    K,
    Keyword,
    Namespace,
    Enum,
    Symbol,
    List,
    csl,
    flag,
    optional,
    attr,
    name,
    parse,
)
from ethpector.utils import (
    keccak,
    function_sig_to_hash,
    strip_function_selector,
    hex_str_to_bytes,
    strip_0x,
    flat,
)

Symbol.regex = re.compile(r"[\w_]+")  # allow underline
Keyword.regex = re.compile(r"[\w\[\]]+")  # allow angle brackets in types


def create_type(string, f, t, s):
    return [K(f"{string}{i}") for i in range(f, t + f, s)]


def add_array_types(types):
    return types + flat(
        [
            list(map(lambda x: K(f"{str(x)}[{str(n)}]"), types))
            for n in (list(range(1, 20)) + [""])
        ]
    )


SOLIDITY_TYPES = add_array_types(
    [K("string"), K("bool"), K("bytes"), K("address")]
    + create_type("uint", 8, 256, 8)
    + create_type("int", 8, 256, 8)
    + create_type("bytes", 1, 32, 1)
)


class Type(Keyword):
    grammar = Enum(*SOLIDITY_TYPES)


class Visibility(Keyword):
    grammar = Enum(K("internal"), K("external"), K("public"))


class Modifier(Keyword):
    grammar = Enum(K("pure"), K("view"), K("payable"), K("constant"))


class EventParamModifier(Keyword):
    grammar = Enum(K("indexed"))


class FunctionParamModifier(Keyword):
    grammar = Enum(K("calldata"), K("memory"), K("storage"), K("payable"))


class EventParameter:
    grammar = (
        attr("type", Type),
        attr("indexed", optional(EventParamModifier)),
        optional(name()),
    )


class NormalParam:
    grammar = (
        attr("type", Type),
        attr("modifier", optional(FunctionParamModifier)),
        optional(name()),
    )


class TupleParam(List):
    grammar = ("(", csl(NormalParam), ")", flag("is_array", K("[]")))


class ReturnParameter:
    grammar = attr("type", Type), optional(name())


class EventParameters(Namespace):
    grammar = optional(csl(EventParameter))


class FunctionParameters(List):
    grammar = optional(csl([NormalParam, TupleParam]))


class ReturnParameters(Namespace):
    grammar = optional(csl(ReturnParameter))


class ReturnValue:
    grammar = "returns", "(", attr("params", ReturnParameters), ")"


class Function:
    grammar = (
        optional("function"),
        name(),
        "(",
        attr("params", FunctionParameters),
        ")",
        attr("visibility", optional(Visibility)),
        attr("modifier", optional(Modifier)),
        attr("ret", optional(ReturnValue)),
    )


class Event:
    grammar = optional("event"), name(), "(", attr("params", EventParameters), ")"


@dataclass
class FunctionDefinition:

    """
    Defines and parses a function prototype. The prototype can then be used to
    match interfaces or decode function calls.
    """

    _ast: object

    @staticmethod
    def _get_param_x(param, attr):
        if type(param) == NormalParam:
            return str(getattr(param, attr))
        elif type(param) == TupleParam:
            p = ",".join([FunctionDefinition._get_param_x(x, attr) for x in param])
            return f"({p})" + ("[]" if param.is_array else "")

    def name(self):
        return self._ast.name

    def params(self):
        return self._ast.params

    def param_types(self):
        return [FunctionDefinition._get_param_x(x, "type") for x in self.params()]

    def param_names(self):
        return [
            str(x.name)
            if hasattr(x, "name") and x.name and not str(x.name).startswith("#")
            else f"param{i+1}"
            for i, x in enumerate(self.params())
        ]

    def visibility(self):
        return str(self._ast.visibility)

    def modifier(self):
        return str(self._ast.modifier)

    def returns(self):
        return self._ast.ret.params.values() if self._ast.ret else []

    def return_types(self):
        return [str(x.type) for x in self.returns()]

    def return_names(self):
        return [
            str(x.name) if x.name and not str(x.name).startswith("#") else f"ret{i+1}"
            for i, x in enumerate(self.returns())
        ]

    def hash(self):
        return keccak(self.signature_string())

    def signature_string(self):
        x = ",".join(self.param_types())
        return f"{self.name()}({x})"

    def selector(self):
        return function_sig_to_hash(self.signature_string())

    def decode_input_parameters(self, hex_input):
        hex_input = strip_0x(hex_input)
        if not hex_input.startswith(strip_0x(self.selector())):
            return None
        abi_input = hex_str_to_bytes(strip_function_selector(hex_input))
        decoded = eth_abi.abi.decode_abi(self.param_types(), abi_input)
        return list(decoded) if decoded else None

    def decode_input_to_str(self, hex_input):
        params = self.decode_input_parameters(hex_input)
        param_names = self.param_names()
        if params:
            return "{}({})".format(
                self.name(),
                ", ".join([f"{x}={y}" for x, y in zip(param_names, params)]),
            )
        else:
            return None

    def __init__(self, str_rep):
        self._ast = parse(str_rep, Function)

    @staticmethod
    def try_get_selector(definition):
        try:
            return FunctionDefinition(definition).selector()
        except SyntaxError:
            return definition


@dataclass
class EventDefinition:

    """
    Defines and parses an event prototype. The prototype can then be used to
    match interfaces or decode event logs.
    """

    _ast: object

    def name(self):
        return self._ast.name

    def params(self):
        return self._ast.params.values()

    def param_types(self):
        return [str(x.type) for x in self.params()]

    def param_indexed(self):
        return [str(x.indexed) if x.indexed else None for x in self.params()]

    def param_names(self):
        return [
            str(x.name) if x.name and not str(x.name).startswith("#") else f"param{i+1}"
            for i, x in enumerate(self.params())
        ]

    def signature_string(self):
        x = ",".join(self.param_types())
        return f"{self.name()}({x})"

    def hash(self):
        return keccak(self.signature_string())

    def selector(self):
        return self.hash()

    def __init__(self, str_rep):
        self._ast = parse(str_rep, Event)

    @staticmethod
    def try_get_selector(definition):
        try:
            return EventDefinition(definition).selector()
        except SyntaxError:
            return definition
