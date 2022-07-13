from ethpector.utils import (
    function_sig_to_hash,
    strip_0x,
    to_int,
    keccak,
    get_function_selector,
    strip_function_selector,
    parse_address_from_storage,
    bytes_to_hex,
)


def test_keccak_works(capsys):
    assert (
        keccak("Transfer(address,address,uint256)")
        == "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
    )


def test_btoh_works(capsys):
    assert bytes_to_hex(b"") is None


def test_function_encoding_works(capsys):
    assert function_sig_to_hash("transfer(address,uint256)") == "0xa9059cbb"


def test_strip_0x_works1():
    assert strip_0x("0xa9059cbb") == "a9059cbb"


def test_strip_0x_works2():
    assert strip_0x("a9059cbb") == "a9059cbb"


def test_to_int1():
    assert to_int(0) == 0
    assert to_int("1111") == 1111
    assert to_int("0xf") == 15
    assert to_int("0x10") == 16


def test_to_getfuncsel():
    assert get_function_selector("a9059cbb") == "a9059cbb"
    assert get_function_selector("0xa9059cbb") == "a9059cbb"
    assert get_function_selector("a9059cbb56654646") == "a9059cbb"
    assert get_function_selector("0xa9059cbb883asdf4sf") == "a9059cbb"
    assert get_function_selector("0xa905") is None
    assert get_function_selector("0x") is None
    assert get_function_selector("") is None
    assert get_function_selector("a9059cb") is None
    assert get_function_selector("0xa9059cb") is None
    assert get_function_selector(None) is None


def test_strip_selector():
    hs = (
        "f31a69690000000000000000000000000000000000000000000000000000000000000"
        "020000000000000000000000000000000000000000000000000000000000000000863"
        "616c6c20666f6f000000000000000000000000000000000000000000000000"
    )

    hs2 = (
        "0000000000000000000000000000000000000000000000000000000000000"
        "020000000000000000000000000000000000000000000000000000000000000000863"
        "616c6c20666f6f000000000000000000000000000000000000000000000000"
    )

    assert strip_function_selector(hs) == hs2


def test_parse_storage_address_works1():
    assert parse_address_from_storage(
        "0000000000000000000000010000000000000000000000000000000000000001"
    ) == ("0x0000000000000000000000000000000000000001", True, False)
    assert parse_address_from_storage(
        "0000000000000000000000a839d4b5a36265795eba6894651a8af3d0ae2e6800"
    ) == ("0xa839d4b5a36265795eba6894651a8af3d0ae2e68", True, True)
    assert parse_address_from_storage(
        "a839d4b5a3626a9d4b5a333839d4b5a36265795eba6894651a8af3d0ae2e6800"
    ) == (
        "0xa839d4b5a3626a9d4b5a333839d4b5a36265795eba6894651a8af3d0ae2e6800",
        False,
        False,
    )
