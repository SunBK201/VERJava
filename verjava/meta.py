from __future__ import annotations

from functools import cached_property

from .util import NODETEXT, Node, child_by_type_name, children_by_type_name, parser


class Package:
    def __init__(self, source_code: str):
        self.source_code = source_code
        self.node = parser.parse(self.source_code)

    @cached_property
    def name(self) -> str:
        package_declaration = child_by_type_name(self.node, "package_declaration")
        if package_declaration is None:
            raise ValueError("The source code does not contain a package declaration.")
        return NODETEXT(
            child_by_type_name(
                package_declaration,
                "scoped_identifier",
            )
        )

    @cached_property
    def classes(self) -> list[Class]:
        class_declarations = children_by_type_name(self.node, "class_declaration")
        return [
            Class(class_declaration, self) for class_declaration in class_declarations
        ]


class Class:
    def __init__(self, class_declaration: Node, package: Package):
        self.class_declaration = class_declaration
        self.package: Package = package

    @cached_property
    def name(self) -> str:
        return NODETEXT(self.class_declaration.child_by_field_name("name"))

    @cached_property
    def qualified_name(self) -> str:
        return self.package.name + "." + self.name

    @cached_property
    def start_line(self) -> int:
        return self.class_declaration.start_point[0] + 1

    @cached_property
    def end_line(self) -> int:
        return self.class_declaration.end_point[0] + 1

    @cached_property
    def source_code(self) -> str:
        return NODETEXT(self.class_declaration)

    @cached_property
    def body_start_line(self) -> int:
        class_body = self.class_declaration.child_by_field_name("body")
        if class_body is None:
            raise ValueError("The class declaration does not contain a body.")
        return class_body.start_point[0] + 1

    @cached_property
    def body_end_line(self) -> int:
        class_body = self.class_declaration.child_by_field_name("body")
        if class_body is None:
            raise ValueError("The class declaration does not contain a body.")
        return class_body.end_point[0] + 1

    @cached_property
    def methods(self) -> list[Method]:
        class_body = self.class_declaration.child_by_field_name("body")
        if class_body is None:
            raise ValueError("The class declaration does not contain a body.")
        method_declarations = children_by_type_name(class_body, "method_declaration")
        return [
            Method(method_declaration, self)
            for method_declaration in method_declarations
        ]


class Method:
    def __init__(self, method_declaration: Node, clazz: Class):
        self.method_declaration = method_declaration
        self.clazz: Class = clazz
        self.package: Package = clazz.package

    @cached_property
    def name(self) -> str:
        return NODETEXT(self.method_declaration.child_by_field_name("name"))

    @cached_property
    def source_code(self) -> str:
        return NODETEXT(self.method_declaration)

    @cached_property
    def start_line(self) -> int:
        return self.method_declaration.start_point[0] + 1

    @cached_property
    def end_line(self) -> int:
        return self.method_declaration.end_point[0] + 1

    @cached_property
    def signature(self) -> str:
        parameters_node = self.method_declaration.child_by_field_name("parameters")
        if parameters_node is None:
            raise ValueError("The method declaration does not contain parameters node")
        parameters = children_by_type_name(parameters_node, "formal_parameter")
        parameters_type_list = [
            NODETEXT(parameter.child_by_field_name("type")) for parameter in parameters
        ]
        return (
            self.clazz.qualified_name
            + "."
            + self.name
            + "("
            + ",".join(parameters_type_list)
            + ")"
        )

    @cached_property
    def body_source_code(self) -> str:
        body = self.method_declaration.child_by_field_name("body")
        if body is None:
            return ""
        return NODETEXT(body)

    @cached_property
    def body_start_line(self) -> int:
        body = self.method_declaration.child_by_field_name("body")
        if body is None:
            return 0
        return body.start_point[0] + 1

    @cached_property
    def body_end_line(self) -> int:
        body = self.method_declaration.child_by_field_name("body")
        if body is None:
            return 0
        return body.end_point[0] + 1
