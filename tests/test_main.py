import json
import pytest

from ethpector.main import main, extract_information
from ethpector.config import Configuration
from ethpector.data.signatures import add_to_signature_db

__author__ = "soad003"
__copyright__ = "soad003"
__license__ = "MIT"

# examples/basic owner
CODE = """
608060405234801561001057600080fd5b50600436106100365760003560e01c8063893d20e81461
003b578063a6f9dae114610059575b600080fd5b610043610075565b60405161005091906103c456
5b60405180910390f35b610073600480360381019061006e91906102fa565b61009e565b005b6000
8060009054906101000a900473ffffffffffffffffffffffffffffffffffffffff16905090565b60
008054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffff
ffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff16146101
2c576040517f08c379a0000000000000000000000000000000000000000000000000000000008152
600401610123906103df565b60405180910390fd5b8073ffffffffffffffffffffffffffffffffff
ffffff1660008054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffff
ffffffffffffffffffffffffffffffffffff167f342827c97908e5e2f71151c08502a66d44b6f758
e3ac2f1de95f02eb95f0a73560405160405180910390a3806000806101000a81548173ffffffffff
ffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffff
ff1602179055508073ffffffffffffffffffffffffffffffffffffffff1660006113889060405160
2401610212906103ff565b6040516020818303038152906040527ff31a6969000000000000000000
000000000000000000000000000000000000007bffffffffffffffffffffffffffffffffffffffff
ffffffffffffffff19166020820180517bffffffffffffffffffffffffffffffffffffffffffffff
ffffffffff838183161783525050505060405161029c91906103ad565b6000604051808303818588
88f193505050503d80600081146102da576040519150601f19603f3d011682016040523d82523d60
00602084013e6102df565b606091505b50505050565b6000813590506102f481610502565b929150
50565b6000602082840312156103105761030f6104ab565b5b600061031e848285016102e5565b91
505092915050565b61033081610446565b82525050565b60006103418261041f565b61034b818561
042a565b935061035b818560208601610478565b80840191505092915050565b6000610374601383
610435565b915061037f826104b0565b602082019050919050565b6000610397600883610435565b
91506103a2826104d9565b602082019050919050565b60006103b98284610336565b915081905092
915050565b60006020820190506103d96000830184610327565b92915050565b6000602082019050
81810360008301526103f881610367565b9050919050565b60006020820190508181036000830152
6104188161038a565b9050919050565b600081519050919050565b600081905092915050565b6000
82825260208201905092915050565b600061045182610458565b9050919050565b600073ffffffff
ffffffffffffffffffffffffffffffff82169050919050565b60005b838110156104965780820151
8184015260208101905061047b565b838111156104a5576000848401525b50505050565b600080fd
5b7f43616c6c6572206973206e6f74206f776e657200000000000000000000000000600082015250
565b7f63616c6c20666f6f0000000000000000000000000000000000000000000000006000820152
50565b61050b81610446565b811461051657600080fd5b5056fea26469706673582212207df9af01
29728f9e2d511fad0f47031dc6148dad401e98996be0559665c7210764736f6c63430008070033
"""

# def test_fib():
#     """API Tests"""
#     assert fib(1) == 1
#     assert fib(2) == 1
#     assert fib(7) == 13
#     with pytest.raises(AssertionError):
#         fib(-10)


@pytest.mark.slow
def test_main_basicowner(capsys):
    """CLI Tests"""
    # capsys is a pytest fixture that allows asserts agains stdout/stderr
    # https://docs.pytest.org/en/stable/capture.html
    main([CODE, "--offline", "--nodotenv"])
    captured = capsys.readouterr()
    j = json.loads(captured.out)
    fns = [x["name"] for x in j["symbolic"]["functions"]]

    assert "getOwner()" in fns
    assert "changeOwner(address)" in fns
    assert len(j["symbolic"]["sender_constraint_functions"]) >= 1
    assert j["symbolic"]["sender_constraint_functions"][0]["address"] == "0x0"


@pytest.mark.slow
def test_main_basicowner_function_summary(capsys):
    main([CODE, "--output=functions", "--offline", "--nodotenv"])
    captured = capsys.readouterr()
    j = json.loads(captured.out)

    assert len(j) == 2

    change_owner = j[1]
    assert change_owner["entry_point"]["function_name"] == "changeOwner(address)"
    assert len(change_owner["detailed_overview"]) >= 1
    sender_constraint = change_owner["sender_constraint"]
    assert sender_constraint["address"] == "0x0"
    assert sender_constraint["is_storage_address"] is True


@pytest.mark.slow
def test_main_basicowner_call_summary(capsys):
    add_to_signature_db("foo(string)")

    main([CODE, "--output=calls", "--offline", "--nodotenv"])
    captured = capsys.readouterr()
    j = json.loads(captured.out)
    assert len(j) == 1

    c1 = j[0]
    assert c1["detailed_overview"]["tags"]["parsed_call"] == "foo(param1=call foo)"


@pytest.mark.slow
def test_main_basicowner_all(capsys):
    main([CODE, "--output=all", "--offline", "--nodotenv"])
    captured = capsys.readouterr()
    assert "getOwner()" in captured.out
    assert "disassembly.txt" in captured.out


def test_main_gastoken(capsys):
    gastoken = "0x6eb3f879cb30fe243b4dfee438691c043318585733ff"
    main([gastoken, "--offline", "--nodotenv"])
    captured = capsys.readouterr()

    j = json.loads(captured.out)
    fns = [x["name"] for x in j["symbolic"]["functions"]]

    assert len(fns) == 1
    assert len(j["symbolic"]["sender_constraint_functions"]) == 1
    assert (
        j["symbolic"]["sender_constraint_functions"][0]["address"]
        == "0xb3f879cb30fe243b4dfee438691c04"
    )


# https://github.com/Arachnid/evmdis/blob/master/tests/recursive.bin
def test_main_recursive(capsys):
    code = (
        "606060405260e060020a6000350463f8a8fd6d8114601c575b6002565b34600"
        "25760005b60006000602356"
    )
    main([code, "--offline", "--nodotenv"])
    captured = capsys.readouterr()

    json.loads(captured.out)


# https://github.com/Arachnid/evmdis/blob/master/tests/loop.bin
def test_main_loop(capsys):
    code = (
        "606060405260e060020a6000350463f8a8fd6d8114601c575b6002565b34600"
        "257603460005b600a8110156036576001016025565b005b5056"
    )
    main([code, "--offline", "--nodotenv"])
    captured = capsys.readouterr()

    json.loads(captured.out)


# https://github.com/Arachnid/evmdis/blob/master/tests/attack1.bin
def test_main_attack1(capsys):
    code = (
        "6000808080739caf77e5b32583fd5aee70acef5deaed67059622602b5a03f41"
        "580808073c3eba2e7e18ffa583e05fad4f2fa1f63374a0fe0602b5a03f415"
    )
    main([code, "--offline", "--nodotenv"])
    captured = capsys.readouterr()

    json.loads(captured.out)


# https://github.com/Arachnid/evmdis/blob/master/tests/ballot.bin
@pytest.mark.slow
def test_main_ballot1(capsys):
    code = """6060604052341561000c57fe5b604051610b22380380610b2283398101604052
            8080518201919050505b600033600060006101000a81548173ffffffffffffffff
            ffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffff
            ffffffffff160217905550600160016000600060009054906101000a900473ffff
            ffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffff
            ffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260
            200190815260200160002060000181905550600090505b815181101561016b5760
            0280548060010182816100f89190610173565b9160005260206000209060020201
            60005b604060405190810160405280868681518110151561012357fe5b90602001
            906020020151600019168152602001600081525090919091506000820151816000
            0190600019169055602082015181600101555050505b80806001019150506100db
            565b5b50506101d5565b8154818355818115116101a05760020281600202836000
            526020600020918201910161019f91906101a5565b5b505050565b6101d291905b
            808211156101ce57600060008201600090556001820160009055506002016101ab
            565b5090565b90565b61093e806101e46000396000f3006060604052361561008c
            576000357c01000000000000000000000000000000000000000000000000000000
            00900463ffffffff1680630121b93f1461008e578063013cf08b146100ae578063
            2e4176cf146100f15780635c19a95c14610143578063609ff1bd14610179578063
            9e7b8d611461019f578063a3ec138d146101d5578063e2ba53f014610264575bfe
            5b341561009657fe5b6100ac6004808035906020019091905050610292565b005b
            34156100b657fe5b6100cc6004808035906020019091905050610353565b604051
            8083600019166000191681526020018281526020019250505060405180910390f3
            5b34156100f957fe5b610101610387565b604051808273ffffffffffffffffffff
            ffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16
            815260200191505060405180910390f35b341561014b57fe5b6101776004808035
            73ffffffffffffffffffffffffffffffffffffffff169060200190919050506103
            ad565b005b341561018157fe5b6101896106fa565b604051808281526020019150
            5060405180910390f35b34156101a757fe5b6101d3600480803573ffffffffffff
            ffffffffffffffffffffffffffff16906020019091905050610781565b005b3415
            6101dd57fe5b610209600480803573ffffffffffffffffffffffffffffffffffff
            ffff16906020019091905050610881565b60405180858152602001841515151581
            526020018373ffffffffffffffffffffffffffffffffffffffff1673ffffffffff
            ffffffffffffffffffffffffffffff168152602001828152602001945050505050
            60405180910390f35b341561026c57fe5b6102746108de565b6040518082600019
            1660001916815260200191505060405180910390f35b6000600160003373ffffff
            ffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffff
            ffffffffffff168152602001908152602001600020905080600101600090549061
            01000a900460ff16156102f25760006000fd5b60018160010160006101000a8154
            8160ff021916908315150217905550818160020181905550806000015460028381
            548110151561032c57fe5b906000526020600020906002020160005b5060010160
            0082825401925050819055505b5050565b60028181548110151561036257fe5b90
            6000526020600020906002020160005b9150905080600001549080600101549050
            82565b600060009054906101000a900473ffffffffffffffffffffffffffffffff
            ffffffff1681565b60006000600160003373ffffffffffffffffffffffffffffff
            ffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001
            90815260200160002091508160010160009054906101000a900460ff161561040f
            5760006000fd5b5b600073ffffffffffffffffffffffffffffffffffffffff1660
            0160008573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffff
            ffffffffffffffffffffffffffff16815260200190815260200160002060010160
            019054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673
            ffffffffffffffffffffffffffffffffffffffff161415801561053d57503373ff
            ffffffffffffffffffffffffffffffffffffff16600160008573ffffffffffffff
            ffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffff
            ffff16815260200190815260200160002060010160019054906101000a900473ff
            ffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffff
            ffffffffffffffff1614155b156105ac57600160008473ffffffffffffffffffff
            ffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16
            815260200190815260200160002060010160019054906101000a900473ffffffff
            ffffffffffffffffffffffffffffffff169250610410565b3373ffffffffffffff
            ffffffffffffffffffffffffff168373ffffffffffffffffffffffffffffffffff
            ffffff1614156105e65760006000fd5b60018260010160006101000a81548160ff
            021916908315150217905550828260010160016101000a81548173ffffffffffff
            ffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffff
            ffffffffffffff160217905550600160008473ffffffffffffffffffffffffffff
            ffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020
            0190815260200160002090508060010160009054906101000a900460ff16156106
            dd578160000154600282600201548154811015156106b657fe5b90600052602060
            0020906002020160005b50600101600082825401925050819055506106f4565b81
            6000015481600001600082825401925050819055505b5b505050565b6000600060
            0060009150600090505b60028054905081101561077b5781600282815481101515
            61072657fe5b906000526020600020906002020160005b5060010154111561076d
            5760028181548110151561075157fe5b906000526020600020906002020160005b
            506001015491508092505b5b8080600101915050610709565b5b505090565b6000
            60009054906101000a900473ffffffffffffffffffffffffffffffffffffffff16
            73ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffff
            ffffffffffffffffffffff1614158061082a5750600160008273ffffffffffffff
            ffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffff
            ffff16815260200190815260200160002060010160009054906101000a900460ff
            165b156108355760006000fd5b6001600160008373ffffffffffffffffffffffff
            ffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152
            602001908152602001600020600001819055505b50565b60016020528060005260
            406000206000915090508060000154908060010160009054906101000a900460ff
            16908060010160019054906101000a900473ffffffffffffffffffffffffffffff
            ffffffffff16908060020154905084565b600060026108ea6106fa565b81548110
            15156108f657fe5b906000526020600020906002020160005b506000015490505b
            905600a165627a7a7230582070d7df799acac354ad4bd60ad039c33ea5e79ea6b3
            a18a8e9510e8622feba9bc0029"""

    main([code, "--offline", "--nodotenv"])
    captured = capsys.readouterr()

    json.loads(captured.out)


def test_main_create_data_test(capsys):
    code = """608060405234801561001057600080fd5b506004361061002b5760003560e01c8
            063775c300c14610030575b600080fd5b61003861004e565b604051610045919061
            0099565b60405180910390f35b600060405161005c9061007e565b6040518091039
            06000f080158015610078573d6000803e3d6000fd5b50905090565b60d5806100e7
            83390190565b610093816100b4565b82525050565b60006020820190506100ae600
            083018461008a565b92915050565b60006100bf826100c6565b9050919050565b60
            0073ffffffffffffffffffffffffffffffffffffffff8216905091905056fe60806
            0405234801561001057600080fd5b5060b68061001f6000396000f3fe6080604052
            348015600f57600080fd5b506004361060285760003560e01c80633b80a79314602
            d575b600080fd5b60336047565b604051603e9190605d565b60405180910390f35b
            60006001905090565b6057816076565b82525050565b60006020820190506070600
            08301846050565b92915050565b600081905091905056fea2646970667358221220
            64e4378d25b7fd9cb24539554eceefc5101d1ba76fff7e307a36af9779f003df647
            36f6c63430008070033a2646970667358221220a97055132dec26b2ec703727a213
            ca1bcea0d2977b8a7bb3e7f639305532f0fb64736f6c63430008070033"""

    deploy_target = (
        "608060405234801561001057600080fd5b5060b68061001f60003960"
        "00f3fe6080604052348015600f57600080fd5b5060043610602857600"
        "03560e01c80633b80a79314602d575b600080fd5b60336047565b6040"
        "51603e9190605d565b60405180910390f35b60006001905090565b605"
        "7816076565b82525050565b6000602082019050607060008301846050"
        "565b92915050565b600081905091905056fea26469706673582212206"
        "4e4378d25b7fd9cb24539554eceefc5101d1ba76fff7e307a36af9779"
        "f003df64736f6c63430008070033"
    )
    config = Configuration.default(
        offline=False,
        output=["all"],
        tofile=True,
        nodotenv=False,
    )

    analysis = extract_information(
        address=None, code=code.replace("\n", "").replace(" ", ""), config=config
    )
    symsum = analysis.get_summary().symbolic

    assert len(symsum.creates) == 1
    assert repr(symsum.creates[0].data) == deploy_target


@pytest.mark.slow
def test_main_bbs_can_get_cfg(capsys):
    config = Configuration.default(
        offline=False,
        output=["all"],
        tofile=True,
        nodotenv=False,
    )

    analysis = extract_information(address=None, code=CODE, config=config)
    ads = analysis.get_annotated_dissassembly()

    g = ads.get_cfg()

    assert len(g.nodes) == 120
    assert len(g.edges) >= 67
