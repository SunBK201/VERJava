from scubatrace import java_parser
from tree_sitter import Node

parser = java_parser


def children_by_type_name(node: Node, type: str) -> list[Node]:
    node_list = []
    for child in node.named_children:
        if child.type == type:
            node_list.append(child)
    return node_list


def child_by_type_name(node: Node, type: str) -> Node | None:
    for child in node.named_children:
        if child.type == type:
            return child
    return None


def NODETEXT(node: Node | None) -> str:
    if node is None:
        raise ValueError("The node is None.")
    if node.text is None:
        raise ValueError("The node does not contain text.")
    return node.text.decode()
