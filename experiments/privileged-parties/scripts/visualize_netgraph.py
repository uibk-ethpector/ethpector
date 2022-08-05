import sys


def show(folder):
    import matplotlib.pyplot as plt
    from netgraph import Graph
    from graph import build_graph

    graph = build_graph(folder)

    print(graph)

    Graph(graph, edge_width=2.0, arrows=True)
    plt.show()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Please provide folder.")
    show(sys.argv[1])
