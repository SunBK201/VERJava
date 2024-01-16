from tree_sitter import Language, Parser, Node

Language.build_library(
    # Store the library in the `build` directory
    "treesitter/build/languages.so",
    # Include one or more languages
    [
        "treesitter/vendor/tree-sitter-java",
    ],
)
JAVA_LANGUAGE = Language("treesitter/build/languages.so", "java")
parser = Parser()
parser.set_language(JAVA_LANGUAGE)

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
