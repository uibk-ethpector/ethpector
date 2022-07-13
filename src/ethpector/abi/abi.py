from ethpector.data.signatures import add_to_signature_db


class AbiJson:

    """
    Provides convenient functions to deal with ABI definition files (JSON)

    Attributes:
        abi_dict (dict): standard JSON ABI format parsed into a dictionary
    """

    def __init__(self, abi_dict):
        self.abi_dict = abi_dict if abi_dict else []

    @staticmethod
    def get_type(param):
        if param["type"] == "tuple":
            ttypes = ",".join([AbiJson.get_type(x) for x in param["components"]])
            return f"({ttypes})"
        elif param["type"] == "tuple[]":
            ttypes = ",".join([AbiJson.get_type(x) for x in param["components"]])
            return f"({ttypes})[]"
        else:
            return param["type"]

    @staticmethod
    def abi_entry_to_signature(abie):
        par_str = ",".join([AbiJson.get_type(x) for x in abie["inputs"]])
        return f"{abie['name']}({par_str})"

    def get_function_signatures(self) -> list[str]:
        """Extracts the function signatures for the ABI file.

        Returns:
            list[str]: function signatures in the ABI
        """
        return [
            AbiJson.abi_entry_to_signature(x)
            for x in self.abi_dict
            if x["type"] == "function"
        ]

    def add_functions_to_signatureDB(self):
        """Adds the function signatures contained in the ABI file to the
        local function signature database.
        """
        for s in self.get_function_signatures():
            add_to_signature_db(s)
