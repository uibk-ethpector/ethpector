import re
from ethpector.main import extract_information
from ethpector.config import Configuration
from ethpector.utils import parse_address_from_storage

# from ethpector.abi import AbiJson
from ethpector.classify.classification import (
    get_intererfaces_for_event,
    get_intererfaces_for_function,
    get_interface_by_name,
)

from rich.columns import Columns
from rich.console import Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.syntax import Syntax

from argparse import ArgumentParser, BooleanOptionalAction
import warnings

risks = []


def add_risk(category, severity, txt):
    global risks
    risks.append((category, severity, txt))


def heading(c, text):
    style = "bold white on blue"
    c.rule(f"[bold red]{text}", style=style, align="left")


def tf_unicode(bool):
    return "[green]\U00002714" if bool else "[red]\U00002716"


def symblic_var_to_string(symvar):
    if isinstance(symvar, str):
        return symvar

    if symvar.is_symbolic():
        symvar_str = repr(symvar).lower()
        calldata = "calldata" in symvar_str

        storage = "storage" in symvar_str
        c = []
        if calldata:
            c.append("user-input")
        if storage:
            c.append("storage")

        return f"unknown ({','.join(c)})"
    else:
        val = int(symvar.concrete_val())
        if val > 2**8:
            val = hex(val)
        return f"{val}"


def get_canonical_function_name(f):
    if f is None:
        return "not Found", None
    f = f.split(" or ")
    # get the shortest function name,
    # penalize underlines since camel case is more common
    a = sorted(f, key=lambda x: len(x) + (10 * x.count("_")))
    f0 = a[0]
    adendum = f" * ({len(a)})" if len(a) > 1 else ""
    return f0, adendum


def is_known_function(f):
    return "0x" not in f


def get_event_name(online_info, event):
    try:
        res = online_info.first_of(["signatures"]).event_name(event)
        if res is not None:
            lst = list(set(res))
            res = lst[0]
        return res
    except Exception:
        res = None
    return res if res is not None else event


def get_function_name(online_info, function):
    try:
        res = online_info.first_of(["signatures"]).function_name(function)
        if res is not None:
            lst = list(set(res))
            res = lst[0]
        return res
    except Exception:
        res = None
    return res if res is not None else function


def sanetize_function_name(f):
    # unknown functions come without () this confuses
    return f"{f}()" if "(" not in f else f


def get_interface_match(f):
    af = f.split(" or ")
    f, adendum = get_canonical_function_name(f)
    fm = list(get_intererfaces_for_function(sanetize_function_name(f)))
    af.remove(f)
    while len(af) > 0 and len(fm) < 1:
        f = af.pop()
        fm = get_intererfaces_for_function(sanetize_function_name(f))

    return ",".join([inf.name for inf in fm])


def get_general_info_table(
    analysis, summary, interface, account_summary, source_summary
):
    is_sc_available = len(source_summary.source_code.keys()) > 0
    bs = int((len(analysis.get_bytecode()) - 2) / 2)
    table = Table(title="Account Summary", safe_box=True)
    table.add_column("property", justify="right", style="cyan", no_wrap=False)
    table.add_column("", style="magenta", justify="right", max_width=40, no_wrap=False)

    table.add_row("Smart Contract", tf_unicode(account_summary.is_contract))
    table.add_row("Code Available", tf_unicode(is_sc_available))

    bal = account_summary.balance if account_summary.balance is not None else 0
    table.add_row("Balance", f"{bal / (10**18):.3f} ETH")
    table.add_row("Binary Size", f"{bs} bytes")

    if summary.disassembly.meta_data is not None:
        meta_url = summary.disassembly.meta_data.url
        table.add_row("Meta Url", f"{meta_url}")

        if (
            summary.disassembly.meta_data.raw is not None
            and "solc" in summary.disassembly.meta_data.raw
        ):
            table.add_row(
                "Solc Version", f"{summary.disassembly.meta_data.raw['solc']}"
            )
    return table


def get_source_info_table(source_summary):
    c = []
    for source, files in source_summary.source_code.items():
        loc = 0
        for file in files:
            code = file["source_code"][0:-1]
            loc += len(code.split("\n"))

        table = Table(title=source)
        table.add_column("property", justify="right", style="cyan", no_wrap=True)
        table.add_column("", style="magenta", justify="right")

        table.add_row("# Files", f"{len(files)}")
        table.add_row("# LoC", f"{loc}")
        c.append(table)

    if len(source_summary.source_code.items()) == 0:
        c.append(Text("No source-code found", style="bold red"))

    return Panel.fit(Columns(c), title="Source Summary")


def get_public_interface_summary_table(summary, function_summary, online_info):
    function_names = [
        get_canonical_function_name(x.entry_point.function_name)[0]
        for x in function_summary
    ]
    log_names = [
        get_event_name(online_info, hex(x.topic0.concrete_val()))
        for x in summary.symbolic.logs
    ]

    table = Table(title="Public Interface")
    table.add_column("property", justify="right", style="cyan", no_wrap=True)
    table.add_column("", style="magenta", justify="right")

    table.add_row("# Functions", f"{len(function_names)}")
    table.add_row(
        "# known Functions",
        f"{len([x for x in function_names if is_known_function(x)])}",
    )
    table.add_row("# Logs", f"{len(log_names)}")
    table.add_row(
        "# known Logs", f"{len([x for x in log_names if is_known_function(x)])}"
    )

    return table


def get_call_summary_table(summary, online_info):
    calls = [
        (
            call.to.is_symbolic(),
            call.to,
            call.value,
            get_function_name(online_info, call.get_calldata_hex())
            if call.get_calldata_hex()
            else None,
        )
        for call in summary.symbolic.calls
    ]

    table = Table(title="Calls to others")
    table.add_column("property", justify="right", style="cyan", no_wrap=True)
    table.add_column("", style="magenta", justify="right")

    with_target = [True for wt, to, v, f in calls if wt]
    with_f = [True for wt, to, v, f in calls if f]
    with_v = [
        True for wt, to, v, f in calls if not v.is_symbolic() and v.concrete_val() > 0
    ]

    table.add_row("# Calls", f"{len(calls)}")
    table.add_row("# with known target", f"{len(with_target)}")
    table.add_row("# with known function", f"{len(with_f)}")
    table.add_row("# with value", f"{len(with_v)}")

    return table


def get_standards_summary_table(interface):
    table = Table(title="Standardisation")
    table.add_column("property", justify="right", style="cyan", no_wrap=True)

    nr = len(interface.disassembly)

    nr_a = len(interface.address)
    nr_b = len(interface.bytecode)

    table.add_row("# Standards Implemented", f"{nr}")
    table.add_row("known address?", f"{tf_unicode(nr_a > 0)}")
    table.add_row("known program?", f"{tf_unicode(nr_b > 0)}")

    return table


def get_function_for_pc(function_summary, pc):
    canidates = [f for f in function_summary if f.detailed_overview[0].valid_at(pc)]
    if len(canidates) > 0:
        return canidates[0].entry_point.function_name
    else:
        return None


def get_public_interface_details_view(summary, function_summary, online_info):
    table = Table(title="Functions")
    table.add_column("function", justify="right", style="cyan", no_wrap=True)
    table.add_column("known", style="magenta", justify="right")
    table.add_column("payable", style="magenta", justify="right")
    table.add_column("privileged", style="magenta", justify="right")
    table.add_column("standards", style="magenta", justify="right")

    for function in sorted(function_summary, key=lambda x: x.entry_point.function_name):
        f = function.entry_point.function_name
        is_payable = (
            function.detailed_overview[0].is_payable
            if len(function.detailed_overview) > 0
            else False
        )
        f, adendum = get_canonical_function_name(f)
        ifs = get_interface_match(f)
        # ifs = ",".join([inf.name for inf in get_intererfaces_for_function(f)])
        priv = function.sender_constraint is not None
        table.add_row(
            f"{f}{adendum}",
            tf_unicode(is_known_function(f)),
            tf_unicode(is_payable),
            tf_unicode(priv),
            ifs,
        )
        if is_payable:
            add_risk(
                "value-flow",
                "medium",
                f"Contract can receive Ether through function {f}.",
            )

        if re.match("on.*Received", f) is not None:
            add_risk(
                "value-flow",
                "medium",
                f"Contract might receive Tokens indicated by function {f}.",
            )

    tablee = Table(title="Logs", expand=True)
    tablee.add_column("Log", justify="right", style="cyan", no_wrap=True)
    tablee.add_column("known", style="magenta", justify="right")
    tablee.add_column("in function", style="magenta", justify="right")
    tablee.add_column("interface", style="magenta", justify="right")

    log_names = [
        (
            get_event_name(online_info, hex(x.topic0.concrete_val())),
            get_function_for_pc(function_summary, x.pc),
        )
        for x in summary.symbolic.logs
    ]

    for ln, f in sorted(log_names, key=lambda x: x[0]):

        if f is not None:
            f, _ = get_canonical_function_name(f)
        else:
            f = "-"
        ifs = ",".join([inf.name for inf in get_intererfaces_for_event(ln)])
        tablee.add_row(f"{ln}", tf_unicode(is_known_function(ln)), f, ifs)

    return (
        Group(
            table,
            Text("* Alternative names possible! Number of found alternatives in ()"),
        ),
        tablee,
    )


def get_source_code_details_view(source_summary):
    g = Group()
    for source, files in source_summary.source_code.items():
        fg = Group()
        for file in files:
            name = file["file"]
            code = file["source_code"][0:-1]
            fg.renderables.append(
                Panel(
                    Syntax(code, "Solidity", line_numbers=True),
                    title=f"Filename: {name}",
                )
            )

        g.renderables.append(Panel(fg, title=f"Source: {source}"))

    if len(g.renderables) == 0:
        g.renderables.append(
            Panel(Text("No source-code found.", style="bold red"), title="Source")
        )

    return g


def get_standards_detailed_view(summary, function_summary, interface, online_info):
    log_names = [
        get_event_name(online_info, hex(x.topic0.concrete_val()))
        for x in summary.symbolic.logs
    ]
    function_names = [
        function.entry_point.function_name for function in function_summary
    ]
    table = Table(title="Partially Matched Standards", expand=True)
    table.add_column("Match", justify="right", style="cyan", no_wrap=True)
    table.add_column("Match Type", style="magenta", justify="right")
    # table.add_column("Missing", style="magenta", justify="right")

    table_me = Table(title="Missing Standard Logs", expand=True)
    table_me.add_column("Standard", justify="right", style="cyan", no_wrap=True)
    table_me.add_column("Missing", style="magenta", justify="right")

    table_mf = Table(title="Missing Standard Functions", expand=True)
    table_mf.add_column("Standard", justify="right", style="cyan", no_wrap=True)
    table_mf.add_column("Missing", style="magenta", justify="right")

    for x in interface.disassembly:
        inter = get_interface_by_name(x.interface_name)
        event_minus = {y.signature_string() for y in inter.events} - set(log_names)
        functions_in_iterface = [y.signature_string() for y in inter.functions]

        def substring_in_function_name(f, function_names):
            for x in function_names:
                if f in x:
                    return True
            return False

        function_minus = [
            x
            for x in functions_in_iterface
            if not substring_in_function_name(x, function_names)
        ]

        nf = set()
        for me in event_minus:
            nf.add(inter.name)
            table_me.add_row(inter.name, me)

        for mf in function_minus:
            nf.add(inter.name)
            table_mf.add_row(inter.name, mf)

        if len(event_minus) > 0 or len(function_minus) > 0:
            for x in nf:
                add_risk(
                    "standardisation",
                    "low",
                    (
                        f"Contract does not fully implement {x}, {len(event_minus)} "
                        f"logs and {len(function_minus)} functions missing."
                    ),
                )

        table.add_row(inter.name, "interface")

    for x in interface.address:
        table.add_row(x.name, "address", "")

    for x in interface.bytecode:
        table.add_row(x.name, "bytecode", "")

    return table, table_mf, table_me


def get_call_details_view(summary, function_summary, online_info):
    calls = [
        (
            call.to.is_symbolic(),
            call.to,
            call.value,
            get_function_name(online_info, call.get_calldata_selector_hex())
            if call.get_calldata_selector_hex()
            else None,
            call.pc,
            call.data.empty(),
        )
        for call in summary.symbolic.calls
    ]
    table = Table(title="Calls")
    table.add_column("to", justify="right", style="cyan", no_wrap=True)
    table.add_column("calling", style="magenta", justify="right")
    table.add_column("in", style="magenta", justify="right")
    table.add_column("value", style="magenta", justify="right")
    for sym, to, value, f, pc, fallback in calls:
        f_in, _ = get_canonical_function_name(get_function_for_pc(function_summary, pc))
        to_str = symblic_var_to_string(to)
        f_str = f if f is not None else ("unknown" if not fallback else "fallback")
        val_str = symblic_var_to_string(value)
        table.add_row(to_str, f_str, f_in, val_str)

        cv = value.concrete_val()
        if cv is None or int(cv) > 0:
            add_risk(
                "value-flow",
                "medium",
                (
                    f"Contract can send Ether in function {f_in} to {to_str} "
                    "by calling {f_str}."
                ),
            )

        if "transfer" in f_str or "approve" in f_str:
            add_risk(
                "value-flow",
                "high",
                (
                    "Contract likely can send tokens in function "
                    f"{f_in} to {to_str} by calling {f_str}."
                ),
            )

    return table


def get_storage_details_view(address, summary, function_summary, online_info):
    resolver = online_info.first_of(["node"])
    reads = [
        (read.slot.is_symbolic(), read.slot, read.pc)
        for read in summary.symbolic.storage_reads
    ]
    writes = [
        (write.slot.is_symbolic(), write.slot, write.pc)
        for write in summary.symbolic.storage_writes
    ]
    table = Table(title="Storage Slots")
    table.add_column("slot", justify="right", style="cyan", no_wrap=True)
    table.add_column("value", style="magenta", justify="right")
    table.add_column("write in", style="magenta", justify="left", max_width=60)
    table.add_column("read in", style="magenta", justify="left", max_width=60)

    d = {}
    for sym, slot, pc in reads:
        slot_rpr = repr(slot)
        if slot_rpr not in d:
            d[slot_rpr] = {}
            d[slot_rpr]["slot"] = slot
            d[slot_rpr]["reads"] = []
            d[slot_rpr]["writes"] = []
        # table.add_row(slot_str, "", f_in)
        d[slot_rpr]["reads"].append(pc)

    for sym, slot, pc in writes:
        slot_rpr = repr(slot)
        if slot_rpr not in d:
            d[slot_rpr] = {}
            d[slot_rpr]["slot"] = slot
            d[slot_rpr]["reads"] = []
            d[slot_rpr]["writes"] = []
        d[slot_rpr]["writes"].append(pc)

    for k, rw in d.items():
        slot_str = symblic_var_to_string(rw["slot"])
        rf = {
            get_canonical_function_name(get_function_for_pc(function_summary, x))[0]
            for x in rw["reads"]
        }
        wf = {
            get_canonical_function_name(get_function_for_pc(function_summary, x))[0]
            for x in rw["writes"]
        }
        val = ""
        cv = rw["slot"].concrete_val()
        if cv is not None:
            val = resolver.get_storage_at(address, hex(cv)).hex()
        table.add_row(slot_str, val, ",".join(wf), ",".join(rf))

    return table


def get_privileged_details_view(function_summary, online_info):
    sender_const = [x for x in function_summary if x.sender_constraint]
    resolver = online_info.first_of(["node"])
    parties = {}
    lbl = "A"
    fun = {}
    for x in sender_const:
        sc = x.sender_constraint
        if sc.is_storage_address:
            if sc.address.concrete_val() is not None:
                res = resolver.get_storage_at(
                    args.address, hex(sc.address.concrete_val())
                ).hex()
                addr = parse_address_from_storage(res)[0] if res is not None else res
            else:
                addr = sc.address
        else:
            addr = sc.address
        if addr not in parties:
            parties[addr] = lbl
            lbl = chr(ord(lbl) + 1)
        fun[x.entry_point.function_name] = (addr, sc)

    table = Table(title="Privileged Parties")
    table.add_column("address", justify="right", style="cyan", no_wrap=True)
    table.add_column("label", justify="right", style="magenta")
    for addr, lbl in parties.items():
        table.add_row(symblic_var_to_string(addr), lbl)

    table2 = Table(title="Privileged Functions")
    table2.add_column("function", justify="right", style="cyan", no_wrap=True)
    table2.add_column("slot", style="magenta", justify="right")
    table2.add_column("label", style="magenta", justify="right")

    for f, (addr, sc) in fun.items():
        f, adendum = get_canonical_function_name(f)
        table2.add_row(
            f"{f}{adendum}", symblic_var_to_string(sc.address), parties[addr]
        )

    if len(parties.items()) > 0:
        add_risk(
            "control",
            "medium",
            (
                "Centralized control detected, "
                "see privileged parties section for more details."
            ),
        )

    return Columns([table, table2])


def get_risks_detail_view(risks):
    table2 = Table(expand=True)
    table2.add_column("category", justify="right", style="cyan", no_wrap=True)
    table2.add_column("severity", justify="right")
    table2.add_column("description", justify="right")

    for cat, sev, txt in risks:
        if sev == "medium":
            style = "[dark_orange]"
        elif sev == "high":
            style = "[red1]"
        else:
            style = "[green]"
        table2.add_row(cat, sev, style + txt)

    return table2


def main(args, cutoff_time=None):
    from rich.console import Console

    warnings.filterwarnings("ignore")

    config = Configuration.default(
        offline=False,
        output=[
            "sourcecode",
            "known_interfaces",
            "functions",
            "disassembly",
            "storage",
        ],
        tofile=False,
        nodotenv=False,
        execution_timeout=args.max_runtime,
        max_depth=512,
        loop_bound=5,
        create_timeout=60,
        solver_timeout=600000,
        call_depth_limit=10,
        transaction_count=6,
        sender_const_sender_in_index=False,
    )

    # Reading Data
    # with Console(stderr=False).status("Working..."):
    analysis = extract_information(address=args.address, code=None, config=config)
    # fs = analysis.get_sender_constraint_functions()
    # interf = analysis.get_interface_matches(threshold=0.2)
    summary = analysis.get_summary()
    source_summary = analysis.get_source_summary()
    function_summary = analysis.get_function_summary()
    online_info = analysis.get_online_resolver()
    account_summary = online_info.account_summary(args.address)
    # is_sc_available = len(source_summary.source_code.keys()) > 0
    interface = analysis.get_interface_matches(threshold=0.2)

    report_file = "report.html"
    console = Console(record=True, stderr=True, style="")

    general_info_view = get_general_info_table(
        analysis, summary, interface, account_summary, source_summary
    )
    interface_summary_view = get_public_interface_summary_table(
        summary, function_summary, online_info
    )
    call_summary_view = get_call_summary_table(summary, online_info)
    standards_summary_view = get_standards_summary_table(interface)
    source_summary_view = get_source_info_table(source_summary)

    (
        public_functions_details_view,
        public_events_details_view,
    ) = get_public_interface_details_view(summary, function_summary, online_info)
    (
        standards_details_view,
        standards_details_view_mf,
        standards_details_view_me,
    ) = get_standards_detailed_view(summary, function_summary, interface, online_info)

    source_code_details_view = (
        get_source_code_details_view(source_summary)
        if args.show_source
        else Panel(Text("Source-code view disabled."))
    )

    call_details_view = get_call_details_view(summary, function_summary, online_info)
    pp_details_view = get_privileged_details_view(function_summary, online_info)

    storage_details_view = get_storage_details_view(
        args.address, summary, function_summary, online_info
    )

    if len(risks) == 0:
        add_risk("No Risks yet")

    risks_view = get_risks_detail_view(risks)

    console.show_cursor()

    console.print(
        Group(
            Panel(
                Group(
                    Columns(
                        [
                            general_info_view,
                            interface_summary_view,
                            call_summary_view,
                            standards_summary_view,
                        ],
                        equal=True,
                        expand=False,
                    ),
                    source_summary_view,
                ),
                title="General",
            ),
            Panel(Group(risks_view), title="Risks"),
            Panel(
                Group(
                    Columns(
                        [public_functions_details_view]
                        + [
                            Group(
                                public_events_details_view,
                                standards_details_view,
                                standards_details_view_mf,
                                standards_details_view_me,
                            )
                        ]
                    ),
                ),
                title="Public Interface",
            ),
            Panel(Columns([call_details_view]), title="Relations"),
            Panel(pp_details_view, title="Privileged Parties"),
            Panel(storage_details_view, title="Storage"),
            source_code_details_view,
            Panel(
                f"Report is available as html file ({report_file}) "
                "in the current directory.",
                title="Info",
            ),
        )
    )
    console.save_html(report_file)


if __name__ == "__main__":

    parser = ArgumentParser(
        description=(
            "Risk assessment for Ethereum Smart Contracts, Powered by Ethpector"
        ),
        epilog="https://github.com/uibk-ethpector/ethpector",
    )
    parser.add_argument(
        "address",
        type=str,
        help="Address to inspect.",
    )

    parser.add_argument(
        "-r",
        "--max-runtime",
        dest="max_runtime",
        type=int,
        default=60,
        help=("Sets a maximal runtime for data extraction. The more the better"),
    )

    parser.add_argument(
        "--show-source",
        default=True,
        action=BooleanOptionalAction,
        help="Show full source code if avaliable.",
    )

    args = parser.parse_args()

    main(args)
