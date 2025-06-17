from claripy.ast.base import Annotation

class TaintAnnotation(Annotation):
    def __init__(self, tag):
        self.tag = tag
    def __str__(self):
        return f"<{self.tag}>"