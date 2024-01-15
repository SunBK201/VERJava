from tree_sitter import Language, Parser, Node
from commit import Blob

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


class Package:
    def __init__(self, blob: Blob, blob_content: str = None):
        self.source_code = blob_content if blob_content else blob.b_blob_content
        if blob is not None:
            self.file = blob.b_path
        else:
            self.file = ""
        self.tree = parser.parse(self.source_code.encode())
        package_declaration = child_by_type_name(self.tree.root_node, "package_declaration")
        scoped_identifier = child_by_type_name(package_declaration, "scoped_identifier").text.decode()
        self.name = scoped_identifier

        class_declarations = children_by_type_name(
            self.tree.root_node, "class_declaration")
        self.classes: [Class] = [Class(class_declaration, self)
                                 for class_declaration in class_declarations]

class Class:
    def __init__(self, class_declaration: Node, package: Package):
        self.name: str = class_declaration.child_by_field_name("name").text.decode()
        self.qualified_name: str = package.name + "." + self.name
        self.package: Package = package

        class_body = class_declaration.child_by_field_name("body")
        method_declarations = children_by_type_name(class_body, "method_declaration")
        self.methods: [Method] = [Method(method_declaration, self)
                                  for method_declaration in method_declarations]


class Method:
    def __init__(self, method_declaration: Node, clazz: Class):
        self.name: str = method_declaration.child_by_field_name("name").text.decode()
        self.clazz: Class = clazz
        self.line_range: tuple[int, int] = method_declaration.start_point[0] + \
            1, method_declaration.end_point[0] + 1
        self.start_line: int = method_declaration.start_point[0] + 1
        self.end_line: int = method_declaration.end_point[0] + 1

        parameters = children_by_type_name(
            method_declaration.child_by_field_name("parameters"), "formal_parameter")
        parameters_type_list = [parameter.child_by_field_name(
            "type").text.decode() for parameter in parameters]
        self.signature: str = clazz.qualified_name + "." + \
            self.name + "(" + ",".join(parameters_type_list) + ")"

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
