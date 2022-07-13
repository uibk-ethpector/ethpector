import argparse
import os
import sys
import logging
from ethpector import __version__
from ethpector.analysis import CodeAnalysis
from ethpector.data import AggregateProvider, to_json
from ethpector.config import Configuration, RECOGNIZED_OUTPUTS

__author__ = "soad003"
__copyright__ = "soad003"
__license__ = "MIT"

_logger = logging.getLogger(__name__)


class OutputWriter(object):
    """
    The output writer takes care of writing output either to a file
    or to std out. The behavior depends on the config option config.to_file
    Attributes:
        config (Configuration): Configuration of the tool
        header (dict): If data is written to stdout headers are inserted
            between file to make them separable. The field keeps track if header
            was already written for a particular file.
        identifier (str): Defines the folder used to write the output.
            Usually an address of the hash of the bytecode
        open_files (dict): Stores the open files to be closed when the scope
            ends
    """

    def __init__(self, config: Configuration, identifier: str):
        self.config = config
        self.header = {}
        self.open_files = {}
        self.identifier = identifier

    def get_folder(self):
        return os.path.join(self.config.output_dir(), self.identifier)

    def __enter__(self):
        if self.config.to_file():
            os.makedirs(self.get_folder(), exist_ok=True)
        return self

    def get_full_filename(self, filename):
        return os.path.join(self.get_folder(), filename)

    def ensureheader(self, file):
        if (
            self.config.more_than_one_output()
            and not self.config.to_file()
            and file not in self.header
        ):
            print("\n\n" + "-" * 20 + self.get_full_filename(file) + "-" * 20 + "\n\n")
            self.header[file] = True

    def write(self, data, file):
        if self.config.to_file():
            if file not in self.open_files:
                self.open_files[file] = open(self.get_full_filename(file), "w")
            print(data, file=self.open_files[file])
        else:
            self.ensureheader(file)
            print(data)

    def __exit__(self, exc_type, exc_value, tb):
        for k, v in self.open_files.items():
            v.close()

        if self.config.to_file():
            _logger.info(f"Output written to {self.get_folder()}.")

        if exc_value:
            raise exc_value
        return True


# ---- Python API ----
def extract_information(address: str, code: str, config: Configuration) -> CodeAnalysis:
    """
    Provides a high level interface to the ethpector functionality.

    Args:
        address (str): Hex-string of an address prefixed with 0x.
            The address is used to acquire the bytecode to analyze for etherscan or
            a rpc node connection.
        code (str): Hex-string of the bytecode
        config (Configuration): Configuration to use.

    Returns:
        CodeAnalysis: Object wrapping the available data extraction functions.
    """
    online_resolver = AggregateProvider(config)

    code = (
        online_resolver.first_of(["node", "etherscan"]).get_code(address)
        if not code
        else code
    )

    analysis = CodeAnalysis(address, code, config, online_resolver)

    return analysis


def output_result(report: CodeAnalysis, config: Configuration):
    """
    Writes the output based on the current configuration provided.

    Args:
        report (CodeAnalysis): Interface to the analysis data.
        config (Configuration): The configuration defines what data should be
            produced
    """
    with OutputWriter(config, report.get_identifier()) as w:
        if config.to_file():
            w.write(report.get_bytecode(), "bytecode.bin")

        if config.output_summary():
            w.write(report.get_summary().to_json(), "summary.json")

        if config.output_disassembly():
            bbs = report.get_annotated_dissassembly()
            for block in bbs:
                w.write(block, "disassembly.txt")

                for inst in block.instructions:
                    w.write(inst, "disassembly.txt")

            if config.output_basicblocks():
                w.write(bbs.to_json(), "basic_blocks.json")

        if config.output_sourcecode():
            ss = report.get_source_summary()
            w.write(ss.to_json(), "source_code.json")

            code_items = ss.source_code.items() if ss.source_code is not None else []
            for data_source, files in code_items:
                for file in files:
                    file_name = file["file"].replace("/", "_").replace("\\", "_")
                    w.write(
                        file["source_code"],
                        file_name if len(file_name.strip()) > 0 else "no_filename",
                    )

        if config.output_calls():
            w.write(to_json(report.get_call_summary()), "call_summary.json")

        if config.output_storage():
            w.write(to_json(report.get_storage_summary()), "storage_summary.json")

        if config.output_functions():
            w.write(to_json(report.get_function_summary()), "function_summary.json")

        if config.output_known_interfaces():
            w.write(to_json(report.get_interface_matches()), "known_interfaces.json")


# ---- CLI ----
def parse_args(args):
    """
    Parses the arguments provided on the command-line.

    Args:
        args (list): List of command-line arguments.

    Returns:
        Object: Parsed command-line args object
    """
    parser = argparse.ArgumentParser(
        description="ethpector -- getting insights into EVM binaries."
    )
    parser.add_argument(
        "--version",
        action="version",
        version="ethpector {ver}".format(ver=__version__),
    )
    parser.add_argument(
        dest="input",
        help="EVM input bytecode or address if -a is provided.",
        type=str,
        metavar="contract",
    )
    parser.add_argument(
        "-r",
        "--rpc",
        dest="rpc",
        help="Ethereum node RPC url.",
        type=str,
        metavar="rpc",
        default=None,
    )
    parser.add_argument(
        "-e",
        "--etherscan",
        dest="etherscan_token",
        help="Etherscan access token.",
        type=str,
        metavar="etherscan_token",
        default=None,
    )
    parser.add_argument(
        "-c",
        "--concolic",
        dest="concolic",
        help="Symbolic execution engine loads values "
        "(storage state, call targets) from node via RPC.",
        action="store_const",
        const=True,
    )
    parser.add_argument(
        "-v",
        "--verbose",
        dest="loglevel",
        help="set loglevel to INFO.",
        action="store_const",
        const=logging.INFO,
    )
    parser.add_argument(
        "-vv",
        "--very-verbose",
        dest="loglevel",
        help="set loglevel to DEBUG.",
        action="store_const",
        const=logging.DEBUG,
    )
    parser.add_argument(
        "-d",
        "--deploy",
        dest="deploy_code",
        help="Sets if deployment code is provided. EXPERIMENTAL.",
        action="store_const",
        const=True,
    )
    parser.add_argument(
        "-a",
        "--address",
        dest="address",
        help="Analyse address: data is loaded either via RPC or Etherscan.",
        action="store_const",
        const=True,
    )
    parser.add_argument(
        "-f",
        "--tofile",
        dest="tofile",
        help="Dump output as files.",
        action="store_const",
        const=True,
    )
    parser.add_argument(
        "--dont_drop_metadatastring",
        dest="dont_drop_metadatastring",
        help="Includes the metadata string to the bytecode analysis.",
        action="store_const",
        const=True,
    ),
    parser.add_argument(
        "--offline",
        dest="offline",
        help="Do not use any online resources.",
        action="store_const",
        const=True,
    )
    parser.add_argument(
        "--nodotenv",
        dest="nodotenv",
        help="Do not load dotenv file to initialize config values.",
        action="store_const",
        const=True,
    )
    parser.add_argument(
        "--output",
        action="extend",
        nargs="+",
        type=str,
        help="Output that should be produced: " + "|".join(RECOGNIZED_OUTPUTS) + ".",
    )
    parser.add_argument(
        "--output_dir",
        type=str,
        help="Directory to save the results if -f is specified. "
        "Default is ethspector-output/.",
        default="ethpector-output",
    )
    return parser.parse_args(args)


def setup_logging(loglevel):
    """
    Sets up the ethpector logging format.

    Args:
        loglevel (TYPE): Logging.level
    """
    logformat = "[%(asctime)s] %(levelname)s:%(name)s:%(message)s"
    logging.basicConfig(
        level=loglevel, stream=sys.stdout, format=logformat, datefmt="%Y-%m-%d %H:%M:%S"
    )
    if loglevel:
        logging.getLogger("mythril").setLevel(loglevel)


def main(args):
    """
    Main entry point of the ethpector command-line tool.

    Args:
        args (TYPE): Description
    """
    args = parse_args(args)
    config = Configuration(args)

    setup_logging(config.loglevel())
    _logger.info(
        "Doing some work brrrr on {}.....".format(
            "deploy code" if config.deploy_code() else "runtime code"
        )
    )
    _logger.info("Using configuration: {}".format(config))

    if config.offline():
        _logger.warning(
            "Running in offline mode, "
            "results are less descriptive in this mode. Consider online mode!"
        )

    if args.address:
        if args.deploy_code:
            _logger.warning("Deploy code flag ignored if address is provided.")

        address = args.input
        code = None
    else:
        if config.output_sourcecode():
            _logger.warning(
                "Source-code can only be loaded if an address is provided as input."
            )

        if args.deploy_code:
            _logger.warning("Analysis of deploy code is EXPERIMENTAL...")

        address = None
        code = args.input

    report = extract_information(address, code, config)

    output_result(report, config)

    _logger.info("Work done... shutting down")


def run():
    main(sys.argv[1:])


if __name__ == "__main__":
    run()
