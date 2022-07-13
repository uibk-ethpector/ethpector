import re
from dataclasses import dataclass, field
from ethpector.utils import is_hex_string, to_int, strip_0x
from .parser import FunctionDefinition, EventDefinition


# TODO add parent standards, for kind of inheritance
@dataclass
class Interface:

    """
    Represents the description of an common interface found in a smart contact.
    Mostly they represent the interface provides by common patterns or
    standardized systems.
    """

    name: str
    urls: list[str]
    functions: list[FunctionDefinition] = field(default_factory=list)
    optional_functions: list[FunctionDefinition] = field(default_factory=list)
    events: list[EventDefinition] = field(default_factory=list)
    optional_events: list[EventDefinition] = field(default_factory=list)
    magic_constants: list[str] = field(default_factory=list)
    known_addresses: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    optional_errors: list[EventDefinition] = field(default_factory=list)
    official_std: bool = True

    def get_match(self, functions, events, constants):
        fl = {
            x if is_hex_string(x) else FunctionDefinition.try_get_selector(x): True
            for x in functions
        }
        el = {
            x if is_hex_string(x) else EventDefinition.try_get_selector(x): True
            for x in events
        }
        cl = {to_int(x): True for x in constants}

        all_functions = self.functions + self.optional_functions
        laf = len(all_functions)
        all_events = self.events + self.optional_events
        lae = len(all_events)
        all_constants = self.magic_constants
        lac = len(all_constants)

        def _sel_or_str(x):
            if type(x) == str:
                return x
            else:
                return x.selector()

        mf = [x for x in all_functions if _sel_or_str(x) in fl]
        me = [x for x in all_events if _sel_or_str(x) in el]
        mc = [x for x in self.magic_constants if to_int(x) in cl]

        mt = len(mf) + len(me) + len(mc)
        lall = laf + lae + lac

        return InterfaceMatch(
            interface_name=self.name,
            functions_match=(len(mf) / laf) if laf != 0 else 0,
            events_match=(len(me) / lae) if lae != 0 else 0,
            constants_match=(len(mc) / lac) if lac != 0 else 0,
            total_match=(mt / lall) if lall != 0 else 0,
            urls=self.urls,
        )


@dataclass
class KnownBytecode:

    """
    Represents a known piece of bytecode or a regex that matches a common
    type of contract. Examples are gas-tokens etc.
    """

    name: str
    pattern: str
    url: str
    official_std: str = field(default_factory=lambda: True)
    description: str = field(default_factory=lambda: "")

    def is_match(self, bytecode):
        p = re.compile(self.pattern)
        return p.match(strip_0x(bytecode)) is not None


@dataclass
class KnownAddress:

    """Well known addresses. Basically tags on addresses."""

    name: str
    address: str
    chain_id: int = field(default_factory=lambda: 1)


@dataclass
class InterfaceMatch:

    """
    Provides a summary of how well a interface matches a given piece of code.
    """

    interface_name: str
    urls: list[str]
    functions_match: float
    events_match: float
    constants_match: float
    total_match: float


KNOWN_BYTECODES = [
    KnownBytecode(
        name="EIP-1167: Minimal Proxy Contract",
        pattern=(
            r"^363d3d373d3d3d363d73bebebebebebebebebebebebebebebebebebebebe"
            "5af43d82803e903d91602b57fd5bf3$"
        ),
        url="https://eips.ethereum.org/EIPS/eip-1167",
    ),
    KnownBytecode(
        name="EIP-3448: MetaProxy Standard",
        pattern=(
            r"^363d3d373d3d3d3d60368038038091363936013d73[0-9a-fA-F]{40}"
            "5af43d3d93803e603457fd5bf3$"
        ),
        url="https://eips.ethereum.org/EIPS/eip-1167",
    ),
    KnownBytecode(
        name="Gastoken UNRESTRICTED",
        pattern=r"^33ff$",
        url="https://gastoken.io/",
        official_std=False,
    ),  # CALLER, SELFDESTRUCT
    KnownBytecode(
        name="Gastoken push10",
        pattern=r"^69[0-9a-fA-F]{20}3318585733ff$",
        url="https://gastoken.io/",
        official_std=False,
    ),
    KnownBytecode(
        name="Gastoken push11",
        pattern=r"^6a[0-9a-fA-F]{22}3318585733ff$",
        url="https://gastoken.io/",
        official_std=False,
    ),
    KnownBytecode(
        name="Gastoken push12",
        pattern=r"^6b[0-9a-fA-F]{24}3318585733ff$",
        url="https://gastoken.io/",
        official_std=False,
    ),
    KnownBytecode(
        name="Gastoken push13",
        pattern=r"^6c[0-9a-fA-F]{26}3318585733ff$",
        url="https://gastoken.io/",
        official_std=False,
    ),
    KnownBytecode(
        name="Gastoken push14",
        pattern=r"^6d[0-9a-fA-F]{28}3318585733ff$",
        url="https://gastoken.io/",
        official_std=False,
    ),
    KnownBytecode(
        name="Gastoken push15",
        pattern=r"^6e[0-9a-fA-F]{30}3318585733ff$",
        url="https://gastoken.io/",
        official_std=False,
    ),
    KnownBytecode(
        name="Gastoken push16",
        pattern=r"^6f[0-9a-fA-F]{32}3318585733ff$",
        url="https://gastoken.io/",
        official_std=False,
    ),
    KnownBytecode(
        name="Gastoken push17",
        pattern=r"^70[0-9a-fA-F]{34}3318585733ff$",
        url="https://gastoken.io/",
        official_std=False,
    ),
    KnownBytecode(
        name="Gastoken push18",
        pattern=r"^71[0-9a-fA-F]{36}3318585733ff$",
        url="https://gastoken.io/",
        official_std=False,
    ),
    KnownBytecode(
        name="Gastoken push19",
        pattern=r"^72[0-9a-fA-F]{38}3318585733ff$",
        url="https://gastoken.io/",
        official_std=False,
    ),
    KnownBytecode(
        name="Gastoken push20",
        pattern=r"^73[0-9a-fA-F]{40}3318585733ff$",
        url="https://gastoken.io/",
        official_std=False,
    ),
    KnownBytecode(
        name="Gnosis Proxy",
        pattern=(
            r"^00000000000000000000000000000000000000000000000000000000000"
            "00020000000000000000000000000000000000000000000000000000000000"
            "00000aa608060405273ffffffffffffffffffffffffffffffffffffffff600"
            "054167fa619486e00000000000000000000000000000000000000000000000"
            "00000000060003514156050578060005260206000f35b36600080376000803"
            "66000845af43d6000803e60008114156070573d6000fd5b3d6000f3fea2656"
            "27a7a72315820d8a00dc4fe6bf675a9d7416fc2d00bb3433362aa8186b750f"
            "76c4027269667ff64736f6c634300050e00320000000000000000000000000"
            "0000000000000000000$"
        ),
        url="https://github.com/safe-global/safe-contracts/blob/"
        "main/contracts/proxies/GnosisSafeProxy.sol",
        description="as created by 0x76E2cFc1F5Fa8F6a5b3fC4c8F4788F0116861F9B",
        official_std=False,
    ),
    KnownBytecode(
        name="Gnosis Proxy",
        pattern=(
            r"^608060405273ffffffffffffffffffffffffffffffffffffffff600054167fa"
            "619486e0000000000000000000000000000000000000000000000000000000060"
            "003514156050578060005260206000f35b3660008037600080366000845af43d6"
            "000803e60008114156070573d6000fd5b3d6000f3fea265627a7a72315820d8a0"
            "0dc4fe6bf675a9d7416fc2d00bb3433362aa8186b750f76c4027269667ff64736"
            "f6c634300050e0032$"
        ),
        url="https://github.com/safe-global/safe-contracts/blob/"
        "main/contracts/proxies/GnosisSafeProxy.sol",
        description="",
        official_std=False,
    ),
]


KNOWN_INTERFACES = [
    Interface(
        name="ERC165",
        functions=[
            FunctionDefinition(
                (
                    "supportsInterface(bytes4 interfaceID) external "
                    "view returns (bool)"
                )
            )
        ],
        urls=["https://eips.ethereum.org/EIPS/eip-165"],
    ),
    Interface(
        name="ERC20",
        functions=[
            FunctionDefinition("totalSupply() public view returns (uint256)"),
            FunctionDefinition(
                ("balanceOf(address _owner) public view " "returns (uint256 balance)")
            ),
            FunctionDefinition(
                (
                    "transfer(address _to, uint256 _value) public "
                    "returns (bool success)"
                )
            ),
            FunctionDefinition(
                (
                    "transferFrom(address _from, address _to, uint256 _value) "
                    "public returns (bool success)"
                )
            ),
            FunctionDefinition(
                (
                    "approve(address _spender, uint256 _value) "
                    "public returns (bool success)"
                )
            ),
            FunctionDefinition(
                (
                    "allowance(address _owner, address _spender) "
                    "public view returns (uint256 remaining)"
                )
            ),
        ],
        optional_functions=[
            FunctionDefinition("name() public view returns (string)"),
            FunctionDefinition("symbol() public view returns (string)"),
            FunctionDefinition("function decimals() public view returns (uint8)"),
        ],
        events=[
            EventDefinition(
                (
                    "Transfer(address indexed _from, "
                    "address indexed _to, uint256 _value)"
                )
            ),
            EventDefinition(
                (
                    "Approval(address indexed _owner, "
                    "address indexed _spender, uint256 _value)"
                )
            ),
        ],
        urls=["https://eips.ethereum.org/EIPS/eip-20"],
    ),
    Interface(
        name="ERC2980",
        functions=[
            FunctionDefinition(
                "frozenlist(address _operator) external view returns (bool)"
            ),
            FunctionDefinition(
                "whitelist(address _operator) external view returns (bool)"
            ),
        ],
        events=[
            EventDefinition(
                "FundsReassigned(address from, address to, uint256 amount)"
            ),
            EventDefinition("FundsRevoked(address from, uint256 amount)"),
            EventDefinition("FundsFrozen(address target)"),
        ],
        urls=["https://eips.ethereum.org/EIPS/eip-2980"],
    ),
    Interface(
        name="EIP-2612: permit - 712-signed approvals",
        functions=[
            FunctionDefinition(
                "permit(address owner, address spender, uint256 value, "
                "uint256 deadline, uint8 v, bytes32 r, bytes32 s)"
            ),
            FunctionDefinition("nonces(address owner)"),
            FunctionDefinition("DOMAIN_SEPARATOR()"),
        ],
        urls=["https://eips.ethereum.org/EIPS/eip-2612"],
    ),
    Interface(
        name="ERC2980-whitelist",
        functions=[
            FunctionDefinition(
                ("addAddressToWhitelist(address _operator) external " "returns (bool)")
            ),
            FunctionDefinition(
                (
                    "removeAddressFromWhitelist(address _operator) external "
                    "returns (bool)"
                )
            ),
        ],
        urls=["https://eips.ethereum.org/EIPS/eip-2980"],
    ),
    Interface(
        name="ERC2980-issuable",
        functions=[
            FunctionDefinition(
                ("isIssuer(address _addr) external view " "returns (bool)")
            ),
            FunctionDefinition(
                ("addIssuer(address _operator) external " "returns (bool)")
            ),
            FunctionDefinition(
                "removeIssuer(address _operator) external returns (bool)"
            ),
            FunctionDefinition("transferIssuer(address _newIssuer) external"),
        ],
        urls=["https://eips.ethereum.org/EIPS/eip-2980"],
    ),
    Interface(
        name="ERC2980-issuable",
        functions=[
            FunctionDefinition(
                "post(string calldata content, string calldata tag) public"
            )
        ],
        events=[
            EventDefinition(
                "NewPost(address indexed user, string content, string indexed tag)"
            )
        ],
        known_addresses=[
            KnownAddress(
                name="Social Media instance",
                address="0x000000000000cd17345801aa8147b8D3950260FF",
            )
        ],
        urls=["https://eips.ethereum.org/EIPS/eip-2980"],
    ),
    Interface(
        name="ERC2980-revokableandreassignable",
        functions=[
            FunctionDefinition("revoke(address _from) external"),
            FunctionDefinition("reassign(address _from, address _to) external"),
        ],
        urls=["https://eips.ethereum.org/EIPS/eip-2980"],
    ),
    Interface(
        name="ERC2980-freezable",
        functions=[
            FunctionDefinition(
                "addAddressToFrozenlist(address _operator) external returns (bool)"
            ),
            FunctionDefinition(
                "removeAddressFromFrozenlist(address _operator) external returns (bool)"
            ),
        ],
        urls=["https://eips.ethereum.org/EIPS/eip-2980"],
    ),
    Interface(
        name="ERC721",
        functions=[
            FunctionDefinition(
                "balanceOf(address _owner) external view returns (uint256)"
            ),
            FunctionDefinition(
                "ownerOf(uint256 _tokenId) external view returns (address)"
            ),
            FunctionDefinition(
                (
                    "safeTransferFrom(address _from, address _to, uint256 _tokenId, "
                    "bytes data) external payable"
                )
            ),
            FunctionDefinition(
                (
                    "safeTransferFrom(address _from, address _to, uint256 _tokenId) "
                    "external payable"
                )
            ),
            FunctionDefinition(
                (
                    "transferFrom(address _from, address _to, uint256 _tokenId) "
                    "external payable"
                )
            ),
            FunctionDefinition(
                "approve(address _approved, uint256 _tokenId) external payable"
            ),
            FunctionDefinition(
                "setApprovalForAll(address _operator, bool _approved) external"
            ),
            FunctionDefinition(
                "getApproved(uint256 _tokenId) external view returns (address)"
            ),
            FunctionDefinition(
                (
                    "isApprovedForAll(address _owner, address _operator) external view "
                    "returns (bool)"
                )
            ),
        ],
        optional_functions=[
            FunctionDefinition("name() external view returns (string _name)"),
            FunctionDefinition("symbol() external view returns (string _symbol)"),
            FunctionDefinition(
                "tokenURI(uint256 _tokenId) external view returns (string)"
            ),
        ],
        events=[
            EventDefinition(
                "Transfer(address indexed _from, address indexed _to, "
                "uint256 indexed _tokenId)"
            ),
            EventDefinition(
                "Approval(address indexed _owner, address indexed _approved, "
                "uint256 indexed _tokenId)"
            ),
            EventDefinition(
                "ApprovalForAll(address indexed _owner, "
                "address indexed _operator, bool _approved)"
            ),
        ],
        urls=["https://eips.ethereum.org/EIPS/eip-721"],
    ),
    Interface(
        name="ERC721-enumerable",
        functions=[
            FunctionDefinition("totalSupply() external view returns (uint256)"),
            FunctionDefinition(
                "tokenByIndex(uint256 _index) external view returns (uint256)"
            ),
            FunctionDefinition(
                "tokenOfOwnerByIndex(address _owner, uint256 _index) "
                "external view returns (uint256)"
            ),
        ],
        urls=["https://eips.ethereum.org/EIPS/eip-721"],
    ),
    Interface(
        name="ERC721-token-receiver",
        functions=[
            FunctionDefinition(
                "onERC721Received(address _operator, address _from, "
                "uint256 _tokenId, bytes _data) external returns(bytes4)"
            )
        ],
        urls=["https://eips.ethereum.org/EIPS/eip-721"],
    ),
    Interface(
        name="ERC721-consecutive-transfer-extension",
        events=[
            EventDefinition(
                "ConsecutiveTransfer(uint256 indexed fromTokenId, "
                "uint256 toTokenId, address indexed fromAddress, "
                "address indexed toAddress)"
            )
        ],
        urls="https://eips.ethereum.org/EIPS/eip-2309",
    ),
    Interface(
        name="ERC721-nft-royality-extension",
        functions=[
            FunctionDefinition(
                "royaltyInfo(uint256 _tokenId, uint256 _salePrice) "
                "external view returns (address receiver, "
                "uint256 royaltyAmount)"
            )
        ],
        magic_constants=["0x2a55205a"],
        urls=["https://eips.ethereum.org/EIPS/eip-2981"],
    ),
    Interface(
        name="ERC721-consumable-extension",
        functions=[
            FunctionDefinition(
                "changeConsumer(address _consumer, uint256 _tokenId) external"
            ),
            FunctionDefinition(
                "consumerOf(uint256 _tokenId) external view returns (address)"
            ),
        ],
        events=[
            EventDefinition(
                "ConsumerChanged(address indexed owner, "
                "address indexed consumer, "
                "uint256 indexed tokenId)"
            )
        ],
        urls=["https://eips.ethereum.org/EIPS/eip-4400"],
    ),
    Interface(
        name="ERC777",
        functions=[
            FunctionDefinition("name() external view returns (string memory)"),
            FunctionDefinition("symbol() external view returns (string memory)"),
            FunctionDefinition("totalSupply() external view returns (uint256)"),
            FunctionDefinition(
                "balanceOf(address holder) external view returns (uint256)"
            ),
            FunctionDefinition("granularity() external view returns (uint256)"),
            FunctionDefinition(
                "defaultOperators() external view returns (address[] memory)"
            ),
            FunctionDefinition(
                "isOperatorFor(address operator, address holder) "
                "external view returns (bool)"
            ),
            FunctionDefinition("authorizeOperator(address operator) external"),
            FunctionDefinition("revokeOperator(address operator) external"),
            FunctionDefinition(
                "send(address to, uint256 amount, bytes calldata data) external"
            ),
            FunctionDefinition(
                "operatorSend(address from, address to, uint256 amount, "
                "bytes calldata data, bytes calldata operatorData) external"
            ),
            FunctionDefinition("burn(uint256 amount, bytes calldata data) external"),
            FunctionDefinition(
                "operatorBurn(address from, uint256 amount, "
                "bytes calldata data, bytes calldata operatorData) external"
            ),
        ],
        events=[
            EventDefinition(
                "Sent(address indexed operator, address indexed from, "
                "address indexed to, uint256 amount, "
                "bytes data, bytes operatorData)"
            ),
            EventDefinition(
                "Burned(address indexed operator, address indexed from, "
                "uint256 amount, bytes data, bytes operatorData)"
            ),
            EventDefinition(
                "AuthorizedOperator(address indexed operator, "
                "address indexed holder)"
            ),
            EventDefinition(
                "RevokedOperator(address indexed operator, address indexed holder)"
            ),
        ],
        urls=["https://eips.ethereum.org/EIPS/eip-777"],
    ),
    Interface(
        name="ERC777-token-receiver",
        functions=[
            FunctionDefinition(
                "tokensReceived(address operator, address from, address to, "
                "uint256 amount, bytes calldata data, "
                "bytes calldata operatorData) external"
            ),
        ],
        urls=["https://eips.ethereum.org/EIPS/eip-777"],
    ),
    Interface(
        name="ERC1363-token-receiver",
        functions=[
            FunctionDefinition(
                "onTransferReceived(address operator, address from, "
                "uint256 value, bytes memory data) external returns (bytes4)"
            )
        ],
        urls=["https://eips.ethereum.org/EIPS/eip-1363"],
    ),
    Interface(
        name="ERC1363-token-sender",
        functions=[
            FunctionDefinition(
                "onApprovalReceived(address owner, uint256 value, "
                "bytes memory data) external returns (bytes4)"
            )
        ],
        urls=["https://eips.ethereum.org/EIPS/eip-1363"],
    ),
    Interface(
        name="ERC1363",
        functions=[
            FunctionDefinition(
                "transferAndCall(address to, uint256 value) external returns (bool)"
            ),
            FunctionDefinition(
                "transferAndCall(address to, uint256 value, bytes memory data) "
                "external returns (bool)"
            ),
            FunctionDefinition(
                "transferFromAndCall(address from, address to, uint256 value) "
                "external returns (bool)"
            ),
            FunctionDefinition(
                "transferFromAndCall(address from, address to, uint256 value, "
                "bytes memory data) external returns (bool)"
            ),
            FunctionDefinition(
                "approveAndCall(address spender, uint256 value) external returns (bool)"
            ),
            FunctionDefinition(
                "approveAndCall(address spender, uint256 value, "
                "bytes memory data) external returns (bool)"
            ),
        ],
        urls=["https://eips.ethereum.org/EIPS/eip-1363"],
    ),
    Interface(
        name="ERC1155",
        functions=[
            FunctionDefinition(
                "safeTransferFrom(address _from, address _to, uint256 _id, "
                "uint256 _value, bytes calldata _data) external"
            ),
            FunctionDefinition(
                "safeBatchTransferFrom(address _from, address _to, "
                "uint256[] calldata _ids, uint256[] calldata _values, "
                "bytes calldata _data) external"
            ),
            FunctionDefinition(
                "balanceOf(address _owner, uint256 _id) external view "
                "returns (uint256)"
            ),
            FunctionDefinition(
                "balanceOfBatch(address[] calldata _owners, "
                "uint256[] calldata _ids) external view returns (uint256[] memory)"
            ),
            FunctionDefinition(
                "setApprovalForAll(address _operator, bool _approved) external"
            ),
            FunctionDefinition(
                "isApprovedForAll(address _owner, address _operator) "
                "external view returns (bool)"
            ),
        ],
        magic_constants=["0xd9b67a26", "0x4e2312e0", "0xf23a6e61", "0xbc197c81"],
        events=[
            EventDefinition(
                "TransferSingle(address indexed _operator, "
                "address indexed _from, address indexed _to, "
                "uint256 _id, uint256 _value)"
            ),
            EventDefinition(
                "TransferBatch(address indexed _operator, "
                "address indexed _from, "
                "address indexed _to, uint256[] _ids, uint256[] _values)"
            ),
            EventDefinition(
                "ApprovalForAll(address indexed _owner, "
                "address indexed _operator, bool _approved)"
            ),
            EventDefinition("URI(string _value, uint256 indexed _id)"),
        ],
        urls=["https://eips.ethereum.org/EIPS/eip-1155"],
    ),
    Interface(
        name="ERC1155-metadata-extension",
        functions=[
            FunctionDefinition(
                "function uri(uint256 _id) external view " "returns (string memory)"
            )
        ],
        urls=["https://eips.ethereum.org/EIPS/eip-1155"],
    ),
    Interface(
        name="ERC1155-token-receiver",
        functions=[
            FunctionDefinition(
                "onERC1155Received(address _operator, address _from, "
                "uint256 _id, uint256 _value, "
                "bytes calldata _data) external returns(bytes4)"
            ),
            FunctionDefinition(
                "onERC1155BatchReceived(address _operator, address _from, "
                "uint256[] calldata _ids, uint256[] calldata _values, "
                "bytes calldata _data) external returns(bytes4)"
            ),
        ],
        events=[
            EventDefinition(
                "TransferSingle(address indexed _operator, "
                "address indexed _from, address indexed _to, "
                "uint256 _id, uint256 _value)"
            ),
            EventDefinition(
                "TransferBatch(address indexed _operator, "
                "address indexed _from, address indexed _to, "
                "uint256[] _ids, uint256[] _values)"
            ),
            EventDefinition(
                "ApprovalForAll(address indexed _owner, "
                "address indexed _operator, bool _approved)"
            ),
            EventDefinition("URI(string _value, uint256 indexed _id)"),
        ],
        urls=["https://eips.ethereum.org/EIPS/eip-1155"],
    ),
    Interface(
        name="ERC4626",
        functions=[
            FunctionDefinition(
                "asset() external view returns(address assetTokenAddress)"
            ),
            FunctionDefinition(
                "totalAssets() external view returns(uint256 totalManagedAssets)"
            ),
            FunctionDefinition(
                "convertToShares(address assets) external view "
                "returns(uint256 shares)"
            ),
            FunctionDefinition(
                "convertToAssets(uint256 share) external view "
                "returns(address assets)"
            ),
            FunctionDefinition(
                "maxDeposit(address receiver) external view "
                "returns(uint256 maxAssets)"
            ),
            FunctionDefinition(
                "previewDeposit(uint256 assets) external view "
                "returns(uint256 shares)"
            ),
            FunctionDefinition(
                "deposit(uint256 assets, address receiver) external "
                "returns(uint256 shares)"
            ),
            FunctionDefinition(
                "maxMint(address receiver) external view " "returns(uint256 maxShares)"
            ),
            FunctionDefinition(
                "previewMint(uint256 shares) external view " "returns(uint256 assets)"
            ),
            FunctionDefinition(
                "mint(uint256 shares, address receiver) external "
                "returns(uint256 assets)"
            ),
            FunctionDefinition(
                "maxWithdraw(address owner) external view " "returns(uint256 maxAssets)"
            ),
            FunctionDefinition(
                "previewWithdraw(uint256 assets) external view "
                "returns(uint256 shares)"
            ),
            FunctionDefinition(
                "maxWithdraw(uint256 assets, address receiver, address owner) external "
                "returns(uint256 shares)"
            ),
            FunctionDefinition(
                "maxRedeem(address owner) external view returns(uint256 maxShares)"
            ),
            FunctionDefinition(
                "previewRedeem(uint256 shares) external view returns(uint256 assets)"
            ),
            FunctionDefinition(
                "redeem(uint256 shares, address receiver, address owner) "
                "external returns(uint256 assets)"
            ),
        ],
        events=[
            EventDefinition(
                "Deposit(address indexed caller, address indexed owner, "
                "uint256 assets, uint256 shares)"
            ),
            EventDefinition(
                "Withdraw(address indexed caller, address indexed receiver, "
                "address indexed owner, uint256 assets, uint256 shares)"
            ),
        ],
        urls=["https://eips.ethereum.org/EIPS/eip-4626"],
    ),
    Interface(
        name="ERC820-Registry",
        functions=[
            FunctionDefinition(
                "getInterfaceImplementer(address _addr, bytes32 _interfaceHash) "
                "external view returns (address)"
            ),
            FunctionDefinition(
                "setInterfaceImplementer(address _addr, bytes32 _interfaceHash, "
                "address _implementer) external"
            ),
            FunctionDefinition(
                "setManager(address _addr, address _newManager) external"
            ),
            FunctionDefinition(
                "getManager(address _addr) public view returns(address)"
            ),
            FunctionDefinition(
                "interfaceHash(string _interfaceName) external pure returns(bytes32)"
            ),
            FunctionDefinition(
                "updateERC165Cache(address _contract, bytes4 _interfaceId) external"
            ),
            FunctionDefinition(
                "implementsERC165Interface(address _contract, "
                "bytes4 _interfaceId) public view returns (bool)"
            ),
            FunctionDefinition(
                "implementsERC165InterfaceNoCache(address _contract, "
                "bytes4 _interfaceId) public view returns (bool)"
            ),
        ],
        magic_constants=[
            "0xf2294ee098a1b324b4642584abe5e09f1da5661c8f789f3ce463b4645bd10aef"
        ],  # keccak256(abi.encodePacked("ERC820_ACCEPT_MAGIC"))
        events=[
            EventDefinition(
                "InterfaceImplementerSet(address indexed addr, "
                "bytes32 indexed interfaceHash, address indexed implementer)"
            ),
            EventDefinition(
                "ManagerChanged(address indexed addr, address indexed newManager)"
            ),
        ],
        known_addresses=[
            KnownAddress(
                name="ERC820 registry",
                address="0x820b586C8C28125366C998641B09DCbE7d4cBF06",
            )
        ],
        urls=["https://eips.ethereum.org/EIPS/eip-820"],
    ),
    Interface(
        name="ERC1820-Registry",
        functions=[
            FunctionDefinition(
                "getInterfaceImplementer(address _addr, bytes32 _interfaceHash) "
                "external view returns (address)"
            ),
            FunctionDefinition(
                "setInterfaceImplementer(address _addr, bytes32 _interfaceHash, "
                "address _implementer) external"
            ),
            FunctionDefinition(
                "setManager(address _addr, address _newManager) external"
            ),
            FunctionDefinition(
                "getManager(address _addr) public view returns(address)"
            ),
            FunctionDefinition(
                "interfaceHash(string calldata _interfaceName) external pure "
                "returns(bytes32)"
            ),
            FunctionDefinition(
                "updateERC165Cache(address _contract, bytes4 _interfaceId) external"
            ),
            FunctionDefinition(
                "implementsERC165Interface(address _contract, "
                "bytes4 _interfaceId) public view returns (bool)"
            ),
            FunctionDefinition(
                "implementsERC165InterfaceNoCache(address _contract, "
                "bytes4 _interfaceId) public view returns (bool)"
            ),
            FunctionDefinition(
                "isERC165Interface(bytes32 _interfaceHash) "
                "internal pure returns (bool)"
            ),
        ],
        magic_constants=[
            "0xa2ef4600d742022d532d4747cb3547474667d6f13804902513b2ec01c848f4b4"
        ],  # keccak256(abi.encodePacked("ERC1820_ACCEPT_MAGIC"))
        events=[
            EventDefinition(
                "InterfaceImplementerSet(address indexed addr, "
                "bytes32 indexed interfaceHash, address indexed implementer)"
            ),
            EventDefinition(
                "ManagerChanged(address indexed addr, " "address indexed newManager)"
            ),
        ],
        known_addresses=[
            KnownAddress(
                name="ERC1820 registry",
                address="0x1820a4B7618BdE71Dce8cdc73aAB6C95905faD24",
            )
        ],
        urls=["https://eips.ethereum.org/EIPS/eip-1820"],
    ),
    Interface(
        name="ENS-registry",
        functions=[
            FunctionDefinition("owner(bytes32 node) constant returns (address)"),
            FunctionDefinition("resolver(bytes32 node) constant returns (address)"),
            FunctionDefinition("ttl(bytes32 node) constant returns (uint64)"),
            FunctionDefinition("setOwner(bytes32 node, address owner)"),
            FunctionDefinition(
                "setSubnodeOwner(bytes32 node, bytes32 label, address owner)"
            ),
            FunctionDefinition("setResolver(bytes32 node, address resolver)"),
            FunctionDefinition("setTTL(bytes32 node, uint64 ttl)"),
        ],
        urls=["https://eips.ethereum.org/EIPS/eip-137"],
    ),
    Interface(
        name="ENS-resolver",
        functions=[FunctionDefinition("addr(bytes32 node) constant returns (address)")],
        events=[EventDefinition("AddrChanged(bytes32 indexed node, address a)")],
        urls=["https://eips.ethereum.org/EIPS/eip-137"],
    ),
    Interface(
        name="ENS-hash-registrar",
        functions=[
            FunctionDefinition("state(bytes32 _hash) constant returns (uint8)"),
            FunctionDefinition(
                "entries(bytes32 _hash) constant returns (uint8, address, "
                "uint256, uint256, uint256)"
            ),
            FunctionDefinition(
                "getAllowedTime(bytes32 _hash) constant returns (uint256 timestamp)"
            ),
            FunctionDefinition(
                "isAllowed(bytes32 _hash, uint256 _timestamp) constant "
                "returns (bool allowed)"
            ),
            FunctionDefinition("startAuction(bytes32 _hash)"),
            FunctionDefinition("startAuctions(bytes32[] _hashes)"),
            FunctionDefinition(
                "shaBid(bytes32 hash, address owner, uint256 value, "
                "bytes32 salt) constant returns (bytes32 sealedBid)"
            ),
            FunctionDefinition("newBid(bytes32 sealedBid)"),
            FunctionDefinition(
                "startAuctionsAndBid(bytes32[] hashes, bytes32 sealedBid)"
            ),
            FunctionDefinition(
                "unsealBid(bytes32 _hash, address _owner, uint256 _value, "
                "bytes32 _salt)"
            ),
            FunctionDefinition("cancelBid(bytes32 seal)"),
            FunctionDefinition("finalizeAuction(bytes32 _hash)"),
            FunctionDefinition("transfer(bytes32 _hash, address newOwner)"),
            FunctionDefinition("releaseDeed(bytes32 _hash)"),
            FunctionDefinition("invalidateName(string unhashedName)"),
            FunctionDefinition("eraseNode(bytes32[] labels)"),
            FunctionDefinition("transferRegistrars(bytes32 _hash)"),
        ],
        known_addresses=[
            KnownAddress(
                name="ENS: Eth Name Service",
                address="0x314159265dd8dbb310642f98f50c066173c1259b",
            ),
            KnownAddress(
                name="ENS: ETH Registrar Controller",
                address="0x283af0b28c62c092c9727f1ee09c02ca627eb7f5",
            ),
        ],
        urls=["https://eips.ethereum.org/EIPS/eip-162"],
    ),
    Interface(
        name="ENS-new-resolver",
        functions=[
            FunctionDefinition("name(bytes32 node) constant " "returns (string)")
        ],
        urls=["https://eips.ethereum.org/EIPS/eip-181"],
    ),
    Interface(
        name="ERC3156-flashloan-lender",
        functions=[
            FunctionDefinition(
                "maxFlashLoan(address token) external view returns (uint256)"
            ),
            FunctionDefinition(
                "flashFee(address token, uint256 amount) "
                "external view returns (uint256)"
            ),
            FunctionDefinition(
                "flashLoan(address receiver, address token, uint256 amount, "
                "bytes calldata data) external returns (bool)"
            ),
        ],
        urls="https://eips.ethereum.org/EIPS/eip-3156",
    ),
    Interface(
        name="ERC3156-flashloan-borrower",
        functions=[
            FunctionDefinition(
                "onFlashLoan(address initiator, address token, uint256 amount, "
                "uint256 fee, bytes calldata data) external returns (bytes32)"
            )
        ],
        urls=["https://eips.ethereum.org/EIPS/eip-3156"],
    ),
    Interface(
        name="ERC3156-flashloan-borrower",
        functions=[
            FunctionDefinition(
                "onFlashLoan(address initiator, address token, uint256 amount, "
                "uint256 fee, bytes calldata data) external returns (bytes32)"
            )
        ],
        urls=["https://eips.ethereum.org/EIPS/eip-3156"],
    ),
    Interface(
        name="ERC3668-off-chain-data-retrieval",
        errors=[
            EventDefinition(
                "OffchainLookup(address sender, string[] urls, bytes calldata, "
                "bytes4 callbackFunction, bytes extraData)"
            )
        ],
        urls=["https://eips.ethereum.org/EIPS/eip-3668"],
    ),
    Interface(
        name="Ownership",
        functions=[
            FunctionDefinition("owner() external view returns(address)"),
            FunctionDefinition("transferOwnership(address _newOwner) external"),
        ],
        events=[
            EventDefinition(
                "OwnershipTransferred(address indexed previousOwner, "
                "address indexed newOwner)"
            )
        ],
        urls=["https://eips.ethereum.org/EIPS/eip-173"],
    ),
    Interface(
        name="ERC-1967-proxy",
        functions=[FunctionDefinition("function implementation() returns (address)")],
        optional_events=[
            EventDefinition("Upgraded(address indexed implementation)"),
            EventDefinition("BeaconUpgraded(address indexed beacon)"),
            EventDefinition("AdminChanged(address previousAdmin, address newAdmin)"),
        ],
        magic_constants=[
            "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc",
            "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50",
            "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103",
        ],
        urls=["https://eips.ethereum.org/EIPS/eip-1967"],
    ),
    Interface(
        name="ERC-897-proxy",
        functions=[
            FunctionDefinition("proxyType() public pure returns (uint256 proxyTypeId)"),
            FunctionDefinition(
                "implementation() public view returns (address codeAddr)"
            ),
        ],
        urls=["https://eips.ethereum.org/EIPS/eip-897"],
    ),
    Interface(
        name="ERC-1271",
        functions=[
            FunctionDefinition(
                "sValidSignature(bytes32 _hash, bytes memory _signature)"
            )
        ],
        magic_constants=["0x1626ba7e"],
        urls=["https://eips.ethereum.org/EIPS/eip-1271"],
    ),
    Interface(
        name="ERC-712",
        functions=[],
        magic_constants=[
            "0x8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f"
        ],
        urls=["https://eips.ethereum.org/EIPS/eip-712"],
    ),
    Interface(
        name="GasToken",
        functions=[
            FunctionDefinition("free(uint256 value) public returns (bool success)"),
            FunctionDefinition(
                "freeUpTo(uint256 value) public returns (uint256 freed)"
            ),
            FunctionDefinition(
                "freeFrom(address from, uint256 value) public returns (bool success)"
            ),
            FunctionDefinition(
                "freeFromUpTo(address from, uint256 value) public "
                "returns (uint256 freed)"
            ),
        ],
        known_addresses=[
            KnownAddress(
                name="GST1", address="0x88d60255F917e3eb94eaE199d827DAd837fac4cB"
            ),
            KnownAddress(
                name="GST2", address="0x0000000000b3F879cb30FE243b4Dfee438691c04"
            ),
        ],
        urls=["https://gastoken.io/"],
        official_std=False,
    ),
    Interface(
        name="OpenZeppelin Pause Pattern",
        functions=[FunctionDefinition("paused()")],
        magic_constants=[],
        urls=[
            "https://github.com/OpenZeppelin/openzeppelin-contracts"
            "/blob/master/contracts/security/Pausable.sol"
        ],
        official_std=False,
    ),
    Interface(
        name="Proxy Admin Pattern",
        functions=[
            FunctionDefinition("getProxyImplementation(address proxy)"),
            FunctionDefinition("getProxyAdmin(address proxy)"),
            FunctionDefinition("changeProxyAdmin(address proxy, address newAdmin)"),
            FunctionDefinition("upgrade(address proxy, address implementation)"),
            FunctionDefinition(
                "upgradeAndCall(address proxy, address implementation, bytes data)"
            ),
        ],
        magic_constants=[],
        urls=[
            "https://github.com/OpenZeppelin/openzeppelin-contracts/"
            "blob/master/contracts/proxy/transparent/ProxyAdmin.sol"
        ],
        official_std=False,
    ),
    Interface(
        name="Gnosis Multisig",
        functions=[
            FunctionDefinition("setFallbackHandler(address)"),
            FunctionDefinition("domainSeparator()"),
            FunctionDefinition("removeOwner(address,address,uint256)"),
            FunctionDefinition("VERSION()"),
            FunctionDefinition("disableModule(address,address)"),
            FunctionDefinition("swapOwner(address,address,address)"),
            FunctionDefinition("getThreshold()"),
            FunctionDefinition(
                (
                    "encodeTransactionData(address,uint256,bytes,uint8,uint256,"
                    "uint256,uint256,address,address,uint256)"
                )
            ),
            FunctionDefinition("requiredTxGas(address,uint256,bytes,uint8)"),
            FunctionDefinition("getModulesPaginated(address,uint256)"),
            FunctionDefinition("approveHash(bytes32)"),
            FunctionDefinition(
                (
                    "getTransactionHash(address,uint256,bytes,uint8,uint256,"
                    "uint256,uint256,address,address,uint256)"
                )
            ),
            FunctionDefinition("nonce()"),
            FunctionDefinition("getModules()"),
            FunctionDefinition(
                "setup(address[],uint256,address,bytes,address,address,uint256,address)"
            ),
            FunctionDefinition("changeMasterCopy(address)"),
            FunctionDefinition("signMessage(bytes)"),
            FunctionDefinition("getOwners()"),
            FunctionDefinition("enableModule(address)"),
            FunctionDefinition("changeThreshold(uint256)"),
            FunctionDefinition(
                (
                    "execTransaction(address,uint256,bytes,uint8,uint256,"
                    "uint256,uint256,address,address,bytes)"
                )
            ),
            FunctionDefinition("approvedHashes(address,bytes32)"),
            FunctionDefinition(
                "execTransactionFromModule(address,uint256,bytes,uint8)"
            ),
            FunctionDefinition(
                "execTransactionFromModuleReturnData(address,uint256,bytes,uint8)"
            ),
            FunctionDefinition("signedMessages(bytes32)"),
            FunctionDefinition("getMessageHaSEPsh(bytes)"),
            FunctionDefinition("addOwnerWithThreshold(address,uint256)"),
            FunctionDefinition("isValidSignature(bytes,bytes)"),
        ],
        magic_constants=[],
        urls=[
            "https://github.com/safe-global/safe-contracts/blob/"
            "main/contracts/GnosisSafe.sol"
        ],
        known_addresses=[
            KnownAddress(
                name="Gnosis Master Copy 1.1.1",
                address="0x34CfAC646f301356fAa8B21e94227e3583Fe3F5F",
            ),
        ],
        official_std=False,
    ),
]


class ContractClassifier:

    """Organizes the functionality to match a known piece of code against,
    known interfaces, bytecodes and addresses.
    """

    def is_known_bytecode(self, bytecode) -> KnownBytecode:
        return self.get_known_bytecode(bytecode) is not None

    def get_known_bytecode(self, bytecode) -> KnownBytecode:
        for x in self.find_known_bytecode(bytecode):
            if x.is_match(bytecode):
                return x
        return None

    def find_known_bytecode(self, bytecode) -> list[KnownBytecode]:
        return [x for x in KNOWN_BYTECODES if x.is_match(bytecode)]

    def get_interface_matches(self, functions, events, constants=[], threshold=0.5):
        return list(
            filter(
                lambda y: y.total_match >= threshold,
                map(
                    lambda x: x.get_match(functions, events, constants),
                    KNOWN_INTERFACES,
                ),
            )
        )

    def get_known_contract(self, address) -> KnownAddress:
        for z in self.find_known_contracts(address):
            if z.address.lower() == address.lower():
                return z
        return None

    def find_known_contracts(self, address) -> list[KnownAddress]:
        return [
            y
            for x in KNOWN_INTERFACES
            for y in x.known_addresses
            if y.address.lower() == address.lower()
        ]

    def is_known_contract(self, address):
        return self.find_known_contract(address) is not None
