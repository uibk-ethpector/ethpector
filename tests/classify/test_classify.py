from ethpector.classify import ContractClassifier

__author__ = "soad003"
__copyright__ = "soad003"
__license__ = "MIT"


eip1157_proxy = (
    "0x363d3d373d3d3d363d73bebebebebebebebebebebebebebebebebebebebe"
    "5af43d82803e903d91602b57fd5bf3"
)
eip3449_proxy = (
    "363d3d373d3d3d3d60368038038091363936013d7357f1887a8BF19b14fC0d"
    "F6Fd9B2acc9Af147eA855af43d3d93803e603457fd5bf3"
)
eip3449_proxy2 = (
    "363d3d373d3d3d3d60368038038091363936013d735B38Da6a701c568545"
    "dCfcB03FcB875f56beddC45af43d3d93803e603457fd5bf3"
)

gst2_token = "0x6eb3f879cb30fe243b4dfee438691c043318585733ff"

gnosis_proxy = (
    "0x00000000000000000000000000000000000000000000000000000000000"
    "00020000000000000000000000000000000000000000000000000000000000"
    "00000aa608060405273ffffffffffffffffffffffffffffffffffffffff600"
    "054167fa619486e00000000000000000000000000000000000000000000000"
    "00000000060003514156050578060005260206000f35b36600080376000803"
    "66000845af43d6000803e60008114156070573d6000fd5b3d6000f3fea2656"
    "27a7a72315820d8a00dc4fe6bf675a9d7416fc2d00bb3433362aa8186b750f"
    "76c4027269667ff64736f6c634300050e00320000000000000000000000000"
    "0000000000000000000"
)


def test_isProxy1157_works1(capsys):
    cc = ContractClassifier()
    assert cc.is_known_bytecode(eip1157_proxy) is True


def test_isProxy1157_works2(capsys):
    cc = ContractClassifier()
    assert cc.is_known_bytecode(eip1157_proxy[2:]) is True


def test_isProxy1157_works3(capsys):
    cc = ContractClassifier()
    assert cc.is_known_bytecode(eip1157_proxy[20:]) is False


def test_isProxy3449_works1(capsys):
    cc = ContractClassifier()
    assert cc.is_known_bytecode(eip3449_proxy[2:]) is False


def test_isProxy3449_works2(capsys):
    cc = ContractClassifier()
    assert cc.is_known_bytecode(eip3449_proxy) is True


def test_isProxy3449_works3(capsys):
    cc = ContractClassifier()
    assert cc.is_known_bytecode(eip3449_proxy2) is True


def test_isGastoken(capsys):
    cc = ContractClassifier()
    assert cc.is_known_bytecode(gst2_token) is True


def test_isGnosisProxy(capsys):
    cc = ContractClassifier()
    assert cc.is_known_bytecode(gnosis_proxy) is True


def test_is_erc721_consumable():
    cc = ContractClassifier()

    match = cc.get_interface_matches(
        functions=["changeConsumer(address,uint256)", "consumerOf(uint256)"],
        events=["ConsumerChanged(address,address,uint256)"],
        constants=[],
    )

    assert len(match) == 1
    assert match[0].interface_name == "ERC721-consumable-extension"
    assert match[0].total_match > 0.9
