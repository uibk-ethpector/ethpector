import pytest

from ethpector.classify import FunctionDefinition, EventDefinition

__author__ = "soad003"
__copyright__ = "soad003"
__license__ = "MIT"


def test_function_parser1():
    x = FunctionDefinition("totalSupply() public view returns (uint256)")

    assert x.name() == "totalSupply"
    assert x.param_types() == []
    assert x.param_names() == []
    assert x.return_types() == ["uint256"]
    assert x.return_names() == ["ret1"]


def test_function_parser2():
    x = FunctionDefinition(
        (
            "transferFrom(address _from, address _to, uint256 _value) public "
            "returns (bool success)"
        )
    )

    assert x.name() == "transferFrom"
    assert x.param_types() == ["address", "address", "uint256"]
    assert x.param_names() == ["_from", "_to", "_value"]
    assert x.return_types() == ["bool"]
    assert x.return_names() == ["success"]


def test_function_parser3():
    x = FunctionDefinition(
        "transferFrom(address calldata _from     , address _to, uint256 _value)"
    )

    assert x.name() == "transferFrom"
    assert x.param_types() == ["address", "address", "uint256"]
    assert x.param_names() == ["_from", "_to", "_value"]
    assert x.return_types() == []
    assert x.return_names() == []


def test_function_parser4():
    x = FunctionDefinition("transferFrom(address,address,uint256)")
    y = FunctionDefinition(
        (
            "transferFrom(address _from, address _to , uint256 _value) public "
            "returns (bool success)"
        )
    )

    assert x.selector() == y.selector()


def test_function_parser5():
    with pytest.raises(Exception):
        FunctionDefinition("transferFrom(from)")


def test_function_parser6():
    y = FunctionDefinition(
        "transfer(address _to, uint256 _value) public returns (bool success)"
    )

    assert y.signature_string() == "transfer(address,uint256)"
    assert y.selector() == "0xa9059cbb"


def test_function_parser7():
    with pytest.raises(Exception):
        FunctionDefinition("totalSupply(())")


def test_function_parser8():
    x = FunctionDefinition("totalSupply((bool,uint256))")

    assert x.name() == "totalSupply"
    assert x.param_types() == ["(bool,uint256)"]
    assert x.param_names() == ["param1"]


def test_function_parser9():
    x = FunctionDefinition("totalSupply(address,(bool,uint256),bytes)")

    assert x.name() == "totalSupply"
    assert x.param_types() == ["address", "(bool,uint256)", "bytes"]


def test_function_parser10():
    x = FunctionDefinition("totalSupply((bool,uint256), bytes blub, address)")

    assert x.name() == "totalSupply"
    assert x.param_types() == ["(bool,uint256)", "bytes", "address"]
    assert x.param_names() == ["param1", "blub", "param3"]


def test_function_parser11():
    x = FunctionDefinition(
        "exactInputSingle((address,address,uint24,address,uint256,uint256,uint160))"
    )

    assert x.selector() == "0x04e45aaf"
    assert x.param_types() == [
        "(address,address,uint24,address,uint256,uint256,uint160)"
    ]
    assert x.param_names() == ["param1"]


def test_event_parser1():
    x = EventDefinition(
        (
            "TransferBatch(address indexed _operator, address indexed _from,"
            " address indexed _to, uint256[] _ids, uint256[] _values)"
        )
    )

    assert x.name() == "TransferBatch"
    assert x.param_types() == [
        "address",
        "address",
        "address",
        "uint256[]",
        "uint256[]",
    ]
    assert x.param_indexed() == ["indexed", "indexed", "indexed", None, None]
    assert x.param_names() == ["_operator", "_from", "_to", "_ids", "_values"]


def test_event_parser2():
    x = EventDefinition("Transfer(address,address,uint256)")

    assert x.name() == "Transfer"
    assert x.param_types() == ["address", "address", "uint256"]
    assert x.param_indexed() == [None, None, None]
    assert x.param_names() == ["param1", "param2", "param3"]

    y = EventDefinition(
        "Transfer(address indexed _from ,address indexed _to ,uint256 _value)"
    )

    assert y.name() == "Transfer"
    assert y.param_types() == ["address", "address", "uint256"]
    assert y.param_indexed() == ["indexed", "indexed", None]
    assert y.param_names() == ["_from", "_to", "_value"]

    z = EventDefinition("Transfer(address _from ,address _to ,uint256 _value)")

    assert z.name() == "Transfer"
    assert z.param_types() == ["address", "address", "uint256"]
    assert z.param_indexed() == [None, None, None]
    assert z.param_names() == ["_from", "_to", "_value"]

    k = EventDefinition("Transfer(address indexed ,address indexed ,uint256)")

    assert k.name() == "Transfer"
    assert k.param_types() == ["address", "address", "uint256"]
    assert k.param_indexed() == ["indexed", "indexed", None]
    assert k.param_names() == ["param1", "param2", "param3"]

    assert (
        x.selector()
        == "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
    )
    assert (
        y.selector()
        == "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
    )
    assert (
        z.selector()
        == "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
    )
    assert (
        k.selector()
        == "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
    )


def test_decode_function_input():
    hs = (
        "f31a69690000000000000000000000000000000000000000000000000000000000000"
        "020000000000000000000000000000000000000000000000000000000000000000863"
        "616c6c20666f6f000000000000000000000000000000000000000000000000"
    )

    fd = FunctionDefinition("foo(string)")
    fd2 = FunctionDefinition("foo(string bla)")

    assert fd.decode_input_parameters(hs) == ["call foo"]
    assert fd.decode_input_parameters("0x" + hs) == ["call foo"]
    assert fd.decode_input_to_str(hs) == "foo(param1=call foo)"
    assert fd2.decode_input_to_str(hs) == "foo(bla=call foo)"
