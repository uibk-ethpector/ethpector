from ethpector.data.signatures import SignatureProvider


def test_online_4bytes_event(capsys):
    sp = SignatureProvider()

    # keccak("Transfer(address,address,uint256)")
    #     == "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
    res = sp.lookup_event_4bytes(
        "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
    )
    assert "Transfer(address,address,uint256)" in res


def test_online_4bytes_function(capsys):
    sp = SignatureProvider()

    # 70a08231 == balanceOf(address)
    res = sp.lookup_function_localA4bytes("70a08231")
    assert "balanceOf(address)" in res


def test_online_etherface_event(capsys):
    sp = SignatureProvider()

    # keccak("Transfer(address,address,uint256)")
    #     == "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
    res = sp.lookup_event_etherface(
        "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
    )
    assert "Transfer(address,address,uint256)" in res


def test_online_etherface_function(capsys):
    sp = SignatureProvider()

    # 70a08231 == balanceOf(address)
    res = sp.lookup_function_etherface("70a08231")
    assert "balanceOf(address)" in res
