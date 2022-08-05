def analyze_address_multiprocessing(input_tuple):
    global global_names
    from ethpector.utils import redirect_output
    from ethpector.classify import FunctionDefinition
    from utils import load_dict_from_file
    import logging
    import os

    (
        adr,
        name,
        expected_results_functions,
        expected_results_owners,
        folder,
        cutoff_time,
        tags_file,
    ) = input_tuple

    tags = load_dict_from_file(tags_file)

    if adr.lower() in tags:
        name = tags[adr.lower()]
    else:
        if name is None or len(name) == 0:
            name = adr

    log_file_name = os.path.join(
        f"{folder}", f"{name.replace(' ', '').replace(':','')}_{adr[:10]}_out.txt"
    )
    out_file_name = log_file_name.replace("_out.txt", "_stdout.txt")
    with redirect_output(out_file_name):
        logformat = "[%(asctime)s] %(levelname)s:%(name)s:%(message)s"
        logging.basicConfig(
            filename=log_file_name, filemode="w", format=logformat, level=logging.INFO
        )
        logger = logging.getLogger(__name__)
        if os.path.exists(out_file_name):
            logger.error(
                "Overwriting out file, please remove old files "
                "before running the experiment."
            )

        # setup_logging(logging.INFO)
        return analyze_address(
            adr,
            name,
            [
                FunctionDefinition(x).signature_string() if x != "fallback" else x
                for x in expected_results_functions
            ],
            expected_results_owners,
            folder,
            logger,
            save_results=True,
            cutoff_time=cutoff_time,
        )


def calculate_matchscore(identified, expected):
    from utils import score_accuracy

    tp = len([x for x in identified if x in expected])
    fp = len([x for x in identified if x not in expected])
    fn = len([x for x in expected if x not in identified])
    precision, recall, f1 = score_accuracy(tp, fp, fn)

    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
    }


def analyze_address(
    adr,
    name,
    expected_results,
    expected_results_owners,
    folder,
    logger,
    save_results=False,
    follow_proxies=True,
    cutoff_time=None,
):
    from ethpector.main import extract_information, output_result
    from ethpector.config import Configuration
    from ethpector.utils import bytes_to_hex, TimeIt, parse_address_from_storage
    from ethpector.abi import AbiJson
    from utils import save_dict_to_file
    from dataclasses import asdict
    import pprint
    import os

    pp = pprint.PrettyPrinter(width=80, compact=True)
    config = Configuration.default(
        offline=False,
        output=[
            "sourcecode",
            "known_interfaces",
            "functions",
            "disassembly",
            "storage",
        ],
        tofile=True,
        nodotenv=False,
        execution_timeout=600 if cutoff_time is None else cutoff_time,
        max_depth=512,
        loop_bound=5,
        create_timeout=60,
        solver_timeout=600000,
        call_depth_limit=10,
        transaction_count=6,
        sender_const_sender_in_index=False,
    )
    logger.info(f"Config is set to {config}")
    summary_output = {}
    logger.info(f"Working on address {name} at {adr}")
    timer = TimeIt()
    with timer:
        analysis = extract_information(address=adr, code=None, config=config)
        fs = analysis.get_sender_constraint_functions()
        interf = analysis.get_interface_matches(threshold=0.2)
        summary = analysis.get_summary()
        source_summary = analysis.get_source_summary()
        # currently only node is supported as datasource
        # Etherscan get_storage_at does not work properly
        online_resolver = analysis.get_online_resolver().first_of(["node"])

        abi_raw = analysis.get_source_summary().source_abi
        abi = AbiJson(abi_raw["etherscan"] if "etherscan" in abi_raw else None)

        g_address_summary = asdict(online_resolver.account_summary(adr))

        contractName = source_summary.get_contract_name()

        summary_output["etherscan_abi_available"] = "etherscan" in abi_raw
        summary_output["address_summary"] = g_address_summary
        summary_output["address"] = adr
        summary_output["bytecode_size"] = len(analysis.get_bytecode())
        summary_output["name"] = name + (
            f" ({contractName})" if contractName is not None else ""
        )

        summary_output["coverage"] = asdict(summary.coverage)
        summary_output["eip_mentions_source_code"] = list(
            source_summary.get_erc_mentions()
        )

        abi_signatures = abi.get_function_signatures()
        # Add signatures form abi to local db
        abi.add_functions_to_signatureDB()

        logger.info("Writing results to file:")
        output_result(analysis, config)

        logger.info("\nThe provided code matches the following interfaces:")
        known_interfaces = set(
            [x.interface_name for x in interf.symbolic if x.total_match > 0.6]
            + [x.interface_name for x in interf.disassembly if x.total_match > 0.6]
            + [x.name for x in interf.bytecode]
            + [x.name for x in interf.address]
        )
        logger.info(known_interfaces)
        summary_output["known_interfaces"] = list(known_interfaces)

        implementations_slots_to_check = (
            ["0x0"] if "Gnosis Proxy" in [x.name for x in interf.bytecode] else []
        )
        implementation_contract = online_resolver.get_implementation(
            adr, implementations_slots_to_check
        )
        summary_output["proxy_implementation"] = (
            parse_address_from_storage(implementation_contract)
            if implementation_contract is not None
            else None
        )

        logs = [
            (log.try_get_selector(), log.functions_string())
            for log in summary.symbolic.logs
            if log.try_get_selector() is not None
        ]

        signatures_lookup = analysis.get_online_resolver().first_of(["signatures"])

        def get_event_name(resolver, selector, log):
            try:
                return signatures_lookup.lookup_event(selector)
            except Exception as e:
                log.error(f"Could not resolve event name {e}")
                return None

        summary_output["logs"] = [
            {
                "function": fn,
                "log": get_event_name(signatures_lookup, sel, logger),
            }
            for sel, fn in logs
        ]

        logger.info("\nIt implements the following functions:")
        summary_output["entry_points"] = []
        for x in summary.disassembly.function_entrypoints:
            s = x.functions_string()
            options = s.split(" or ")
            in_abi = False
            for y in options:
                if y in abi_signatures:
                    in_abi = True
                    abi_signatures.remove(y)
            summary_output["entry_points"].append({"name": s, "in_abi": in_abi})
            logger.info(f"{s} which is in abi: {in_abi}")

        logger.info(
            "Could not find the following functions "
            "in the binary that are announced in the abi:"
        )
        summary_output["not_explored_entry_points"] = list(abi_signatures)
        if len(abi_signatures) > 0:
            logger.info(", \n".join(abi_signatures))
        else:
            logger.info("None")

        logger.info(
            "\nParts of the following functions can only be"
            " executed by privileged parties according to its bytecode:"
        )
        fdict = {}
        for x in fs:
            key = (
                x.sender_constraint.address.val(),
                x.sender_constraint.address.is_symbolic(),
                x.sender_constraint.is_storage_address,
                x.sender_constraint.is_probably_mapping,
            )
            if key not in fdict:
                fdict[key] = []
            fdict[key].append(x)

        owners = []
        slots = []
        priv_functions = set()
        summary_output["privileged_functions"] = []
        for (
            caddress,
            is_symbolic,
            is_storage_address,
            is_probably_mapping,
        ), d in fdict.items():

            owner_address = None
            caddress_out = "symbolic"
            if is_symbolic:
                logger.info(
                    "The following functions can only be execute the party "
                    f"encoded at symbolic storage slot {caddress}"
                )
            else:
                caddress_out = hex(caddress)
                try:
                    owner_address = (
                        bytes_to_hex(online_resolver.get_storage_at(adr, caddress))
                        if is_storage_address
                        else hex(caddress)
                    )

                except Exception as e:
                    logger.error(f"Error resolving storage: {e}")
                    raise e
                logger.info(
                    f"The following functions can only be execute by {owner_address}"
                )
                if is_storage_address:
                    logger.info(f"The address is located in storage at {hex(caddress)}")
                else:
                    logger.info("The address is hard coded, thus can't change")

            extracted_address, parsed, shifted = (
                parse_address_from_storage(owner_address)
                if owner_address is not None
                else (None, True, False)
            )

            if parsed is False and shifted and not is_storage_address:
                logger.error(
                    "Address extracted does not look "
                    f"like an address, {owner_address}"
                )

            if shifted:
                logger.info(f"Use shifted address, {owner_address}")

            if extracted_address is not None:
                address_summary = asdict(
                    online_resolver.account_summary(extracted_address)
                )
            else:
                address_summary = None

            if extracted_address is not None:
                owners.append(extracted_address.lower())

            if is_storage_address:
                slots.append(caddress_out)

            summary_entry = {
                "privileged_party": extracted_address,
                "address_summary": address_summary,
                "address": caddress_out,
                "managed_in_storage": is_storage_address,
                "is_probably_mapping": is_probably_mapping,
                "functions": [],
            }

            for z in d:
                summary_entry["functions"].append(z.detailed_overview.name)
                logger.info(pp.pformat(z))

            functions_found = set(summary_entry["functions"])

            if not is_symbolic or config.sender_const_sender_in_index():
                priv_functions |= functions_found

            summary_entry["functions"] = list(functions_found)

            summary_output["privileged_functions"].append(summary_entry)

        logger.info("So the address has the following privileged parties:")
        owners_set = set(owners)
        logger.info(owners_set)
        summary_output["owners"] = list(owners_set)

        admin_slots = list(set(slots))
        summary_output["slots"] = admin_slots

        writes = analysis.get_storage_summary().writes
        writes_at = [
            {
                "function": x.detailed_overview.functions_string(),
                "slot": hex(x.detailed_overview.slot.concrete_val()),
            }
            for x in writes
            if x.detailed_overview is not None
            and x.detailed_overview.slot.concrete_val() is not None
        ]

        summary_output["writes_to_slots"] = [
            x for x in writes_at if x["slot"] in admin_slots
        ]

        def filter_relevant_expected(x, expected_results):
            if " or " in x:
                for y in x.split(" or "):
                    if y.strip() in expected_results:
                        return y
                return x
            else:
                return x

        priv_functions = {
            filter_relevant_expected(x, expected_results) for x in list(priv_functions)
        }

        functions_expected = set(expected_results)
        summary_output["functions_fp"] = list(
            priv_functions.difference(functions_expected)
        )
        summary_output["functions_fn"] = list(
            functions_expected.difference(priv_functions)
        )
        summary_output["match_score"] = calculate_matchscore(
            list(priv_functions), list(functions_expected)
        )

        priv_functions = set()

        owners_expected = set(expected_results_owners)
        summary_output["owners_fp"] = list(owners_set.difference(owners_expected))
        summary_output["owners_fn"] = list(owners_expected.difference(owners_set))
        summary_output["match_score_owners"] = calculate_matchscore(
            list(owners_set), list(owners_expected)
        )
        summary_output["runtime"] = timer.get_seconds()
        if save_results:
            save_dict_to_file(
                os.path.join(
                    f"{folder}",
                    f"{name.replace(' ', '').replace(':', '')}_{adr[:10]}_summary.json",
                ),
                summary_output,
            )
    logger.info(
        f"Was working on address {name} at {adr} for {timer.get_seconds()} seconds."
    )
    if follow_proxies and summary_output["proxy_implementation"] is not None:
        implementation = summary_output["proxy_implementation"][0].lower()
        owners.append(implementation)

    return list(set(owners))


if __name__ == "__main__":
    """testing code"""
    # from ethpector.main import extract_information, output_result, setup_logging
    # from ethpector.config import Configuration
    # from ethpector.utils import bytes_to_hex, TimeIt
    # from ethpector.abi import AbiJson
    # from utils import save_dict_to_file
    # from dataclasses import asdict
    # import pprint
    # import logging
    # import os

    # logger = logging.getLogger(__name__)
    # setup_logging(logging.INFO)
    # pp = pprint.PrettyPrinter(width=80, compact=True)
    # config = Configuration.default(
    #     offline=False,
    #     output=["sourcecode", "known_interfaces", "functions", "disassembly"],
    #     tofile=True,
    #     nodotenv=False,
    # )
    # analysis = extract_information(
    #     address="0xa2327a938Febf5FEC13baCFb16Ae10EcBc4cbDCF", code=None, config=config
    # )
    # online_resolver = analysis.get_online_resolver().first_of(["node"])

    # # # overlapping storage weird
    # print(
    #     bytes_to_hex(
    #         online_resolver.get_storage_at(
    #             "0xa2327a938Febf5FEC13baCFb16Ae10EcBc4cbDCF", 8
    #         )
    #     )
    # )
    # print(
    #     bytes_to_hex(
    #         online_resolver.call(
    #             "0xa2327a938Febf5FEC13baCFb16Ae10EcBc4cbDCF", "0x35d99f35"
    #         )
    #     )
    # )

    # # analyze_address("0xa2327a938Febf5FEC13baCFb16Ae10EcBc4cbDCF",
    # "USD Coin", [], [], None)

    # print(
    #     online_resolver.get_implementation("0x0d02755a5700414B26FF040e1dE35D337DF56218")
    # )
