from ethpector.data.base import DataProvider

# TODO: add swarm and ipfs
# https://api.gateway.ethswarm.org/bzz/a6465fc1ce7ab1a92906ff7206b23d80a21bbd50b85b4bde6a91f8e6b2e3edde/


class SwarmProvider(DataProvider):

    """CURRENTLY not implemented."""

    def __init__(self):
        pass

    def provider_name(self):
        return "swarm"
