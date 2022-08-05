def get_id_for_address(address):
    return address.lower()


def get_title(item):
    address = item["address"]
    c = "CA" if item["address_summary"]["is_contract"] else "EOA"
    funds = item["address_summary"]["balance"]
    has_code = item["etherscan_abi_available"]
    funds = (funds / 10**18) if funds is not None else 0
    c += f"\nEth;{funds}"
    c += f"\nCode;{has_code}"

    c += f'\n<a href="etherscan.io/address/{address}" ' 'target="_blank">etherscan</a>'

    if item["address"] != item["name"]:
        return (
            f"{c}:\n{item['name']}\n "
            f"({item['address']})\n "
            f"{item['known_interfaces']}"
        )
    else:
        return f"{c}\n{item['address']}"


def get_node_group(item):
    # #DFC2F2
    if item["address_summary"]["is_contract"] is False:
        return 4, "#266DD3"
    elif item["address"].count("0") > 30:
        return 3, "#e5e110"
    elif item["etherscan_abi_available"]:
        return 2, "#07841c"
    else:
        return 10, "#e53010"


def get_edge_group(item):
    if item == "owner":
        return 2, "#162347"
    elif item == "implementation":
        return 3, "#dd4b39"
    else:
        return 1, "#000000"


def get_label(item):
    address = item["address"].lower()
    name = item["name"]
    if address == name.lower():
        return address[:6] + "..." + address[-4:]
    else:
        n = 16
        r = [name[i : i + n] for i in range(0, len(name), n)]
        return "\n".join(r)


def build_graph(folder, only_with_owners=True):
    import networkx as nx
    import glob
    import os
    from utils import load_dict_from_file
    from ethpector.utils import flat

    files = glob.glob(os.path.join(f"{folder}", "*_summary.json"))

    nx_graph = nx.DiGraph()
    data = [load_dict_from_file(x) for x in files]

    in_view = {}

    for j in data:
        owners = j["owners"]

        if not only_with_owners or len(owners) > 0:
            in_view[j["address"].lower()] = True

        for owner in owners:
            in_view[owner.lower()] = True

        if j["proxy_implementation"] is not None:
            a = j["proxy_implementation"][0].lower()
            in_view[a] = True

    for address in in_view.keys():
        ident = get_id_for_address(address)
        nx_graph.add_node(ident)
        nx_graph.nodes[ident]["label"] = ident[:6] + "..." + ident[-4:]
        nx_graph.nodes[ident]["title"] = "Implementation wo Owners"

    for j in data:
        address = j["address"]
        owners = j["owners"]

        if not only_with_owners or address.lower() in in_view:
            ident = get_id_for_address(address)

            # nx_graph.add_node(ident)
            group, color = get_node_group(j)
            nx_graph.nodes[ident]["title"] = (
                get_title(j).replace(":", "").replace("\n", "<br>")
            )
            nx_graph.nodes[ident]["label"] = get_label(j).replace(":", "")
            nx_graph.nodes[ident]["group"] = str(group)
            nx_graph.nodes[ident]["color"] = color

    for j in data:
        address = j["address"]
        owners = j["owners"]

        if not only_with_owners or address.lower() in in_view:
            ident = get_id_for_address(address)

            for owner in owners:
                x = [
                    x
                    for x in j["privileged_functions"]
                    if x["privileged_party"]
                    and x["privileged_party"].lower() == owner.lower()
                ]
                n = len(x)

                functions = flat([y["functions"] for y in x])

                title = "<br>".join(functions)

                group, color = get_edge_group("owner")
                nx_graph.add_edge(
                    get_id_for_address(owner),
                    ident,
                    value=str(len(functions)),
                    weight=str(n),
                    title=title,
                    color=color,
                    group=str(group),
                )

            if j["proxy_implementation"] is not None:
                a = j["proxy_implementation"][0].lower()
                group, color = get_edge_group("implementation")
                nx_graph.add_edge(
                    ident,
                    get_id_for_address(a),
                    value=str(1),
                    weight=str(1),
                    title="is implementation",
                    color=color,
                    group=str(group),
                )

    return nx_graph
