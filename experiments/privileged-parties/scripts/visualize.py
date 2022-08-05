import sys


def show(folder, per_component=False, only_with_owners=True):
    from pyvis.network import Network
    import networkx as nx
    from graph import build_graph

    nx_graphs = build_graph(folder, only_with_owners=only_with_owners)

    if per_component:
        graphs = [
            nx_graphs.subgraph(c).copy()
            for c in nx.weakly_connected_components(nx_graphs)
        ]
    else:
        graphs = [nx_graphs]

    for i, nx_graph in enumerate(graphs):

        from networkx.drawing.nx_pydot import graphviz_layout

        pos = graphviz_layout(
            nx_graph, prog="circo"  # if per_component else "twopi"
        )  # twopi | dot
        # pos = nx.kamada_kawai_layout(nx_graph)
        # pos = nx.spectral_layout(nx_graph)
        # pos = nx.circular_layout(nx_graph, scale=3)
        # pos = nx.multipartite_layout(nx_graph)
        # pos = nx.shell_layout(nx_graph)
        # pos = nx.random_layout(nx_graph, center=[500,500])
        # pos = nx.planar_layout(nx_graph)
        pos = nx.rescale_layout_dict(pos, scale=800)

        nt = Network("100%", "100%", directed=True, heading=folder, layout=None)

        # populates the nodes and edges data structures
        nt.from_nx(nx_graph, default_edge_weight=None)  # , show_edge_weights=False)

        # nt.barnes_hut()
        # nt.force_atlas_2based()
        # nt.show_buttons(filter_=['nodes'])
        nt.toggle_physics(False)
        # nt.inherit_edge_colors(False)

        for node in nt.nodes:
            node["x"] = pos[node["id"]][0]
            node["y"] = pos[node["id"]][1]

        to_tikz(i, nt)

        nt.show(f"network_{i}.html")


def to_tikz(i, nt):
    with open(f"network_{i}.tex", "w") as f:
        for node in nt.nodes:
            if "group" in node:
                ntype = "CA" if node["group"] != 4 else "EOA"
            else:
                ntype = ""
            i = node["id"][2:]
            lbl = node["label"].replace("\n", "")[:10]
            f.write(
                (
                    f"\\node[node, {ntype}] "
                    f"at ({node['x']}, {node['y']}) "
                    f"({i}) {{{lbl}}}; % {node}\n"
                )
            )

        for edge in nt.edges:
            # import pdb; pdb.set_trace()
            fr = edge["from"][2:]
            to = edge["to"][2:]
            both_ways = any(
                [
                    x
                    for x in nt.edges
                    if x["from"] == edge["to"] and x["to"] == edge["from"]
                ]
            )
            color = "red" if edge["group"] == 3 else ""
            bw = "bothways" if both_ways else ""
            edge_label = (
                "impl." if color == "red" else (f"{edge['value']} / {edge['weight']}")
            )
            f.write(
                (
                    f"\\draw[->, edge, {bw},  {color}] ({fr}) to "
                    f"node[edgelabel] {{{edge_label}}} "
                    f"({to}); % {edge}\n"
                )
            )


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Please provide folder.")
    show(
        sys.argv[1],
        sys.argv[2].lower() == "true" if len(sys.argv) >= 3 else False,
        sys.argv[3].lower() == "true" if len(sys.argv) >= 4 else False,
    )
