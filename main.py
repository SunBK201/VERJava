import argparse
import logging
from commit import Commit
from meta import Package, Method
from git import Repo
from meta import parser
import definitions

class PatchFunc:
    def __init__(self, signature: str, path: str,
                 a_start_line, a_end_line, b_start_line, b_end_line):
        self.signature = signature
        self.file = path
        self.a_start_line = a_start_line
        self.a_end_line = a_end_line
        self.b_start_line = b_start_line
        self.b_end_line = b_end_line
        self.addline = set()
        self.delline = set()

class TargetFunc:
    def __init__(self, method: Method):
        self.method = method
        self.start_line, self.end_line = method.line_range
        self.line = set()
        self.safe = True

        source_code_lines = method.clazz.package.source_code.split("\n")
        for i in range(self.start_line + 1, self.end_line):
            if source_code_lines[i].strip() == "":
                continue
            self.line.add(source_code_lines[i].strip().replace(" ", ""))


def patch_parser(repo_path: str, commit_id: str) -> list[PatchFunc]:
    patch = Commit(repo_path, commit_id)
    patchFunctions: list[PatchFunc] = []
    for blob in patch.blobs:
        if blob.change_type != "C" or "test/" in blob.a_path:
            continue
        a_package = Package(None, blob.a_blob_content)
        b_package = Package(None, blob.b_blob_content)
        a_methods: set[Method] = set()
        b_methods: set[Method] = set()
        for clazz in a_package.classes:
            for method in clazz.methods:
                a_methods.add(method)
        for clazz in b_package.classes:
            for method in clazz.methods:
                b_methods.add(method)

        tmpPatchFunctions: list[PatchFunc] = []
        for am in a_methods:
            for bm in b_methods:
                if am.signature == bm.signature:
                    tmpPatchFunctions.append(PatchFunc(am.signature, blob.b_path,
                                             am.start_line, am.end_line, bm.start_line, bm.end_line))
                    break

        for hunk in blob.hunks:
            for line, code in hunk.added_lines.items():
                if code.strip() == "" or code.strip().startswith("//"):
                    continue
                for func in tmpPatchFunctions:
                    if func.b_start_line <= line <= func.b_end_line:
                        func.addline.add(code.strip().replace(" ", ""))
            for line, code in hunk.deleted_lines.items():
                if code.strip() == "" or code.strip().startswith("//"):
                    continue
                for func in tmpPatchFunctions:
                    if func.a_start_line <= line <= func.a_end_line:
                        func.delline.add(code.strip().replace(" ", ""))

        for func in tmpPatchFunctions:
            if len(func.addline) != 0 or len(func.delline) != 0:
                patchFunctions.append(func)

    return patchFunctions


def target_parser(repo_path: str, patchFunctions: list[PatchFunc]):
    repo = Repo(repo_path)
    for tag in repo.tags:
        targetFunctions: list[TargetFunc] = []
        targe_commit = repo.commit(tag)

        for func in patchFunctions:
            try:
                target_blob = targe_commit.tree[func.file]
            except:
                continue
            target_package = Package(None, target_blob.data_stream.read().decode())
            for clazz in target_package.classes:
                for method in clazz.methods:
                    if method.signature == func.signature:
                        targetFunctions.append(TargetFunc(method))

        for patchfunc in patchFunctions:
            targetFunc = next((tf for tf in targetFunctions if tf.method.signature ==
                              patchfunc.signature), None)
            if targetFunc is None:
                continue
            targetFuncLineSet = targetFunc.line
            delLineSet_n = len(patchfunc.delline)
            addLineSet_n = len(patchfunc.addline)
            delSim = 0
            addSim = 0
            if delLineSet_n != 0:
                delSim = len(patchfunc.delline & targetFuncLineSet) / delLineSet_n
            if addLineSet_n != 0:
                addSim = len(patchfunc.addline & targetFuncLineSet) / addLineSet_n
            if delLineSet_n != 0 and addLineSet_n != 0:
                if delSim >= definitions.tDel and addSim <= definitions.tAdd:
                    targetFunc.safe = False
                    # print(f"tag: {tag}, delSim: {delSim}, addSim: {addSim}, safe: {targetFunc.safe}")
            elif addLineSet_n == 0:
                if delSim >= definitions.tDel:
                    targetFunc.safe = False
                    # print(f"tag: {tag}, delSim: {delSim}, addSim: {addSim}, safe: {targetFunc.safe}")
            elif delLineSet_n == 0:
                if addSim <= definitions.tAdd:
                    targetFunc.safe = False
                    # print(f"tag: {tag}, delSim: {delSim}, addSim: {addSim}, safe: {targetFunc.safe}")
            else:
                # print(f"tag: {tag}")
                targetFunc.safe = True

        totalNum = len(patchFunctions)
        vulNum = sum(1 for func in targetFunctions if not func.safe)
        for patchfunc in patchFunctions:
            targetFunc = next((tf for tf in targetFunctions if tf.method.signature ==
                              patchfunc.signature), None)
            if targetFunc is None:
                totalNum -= 1

        if totalNum == 0:
            continue
        # print(f"tag: {tag}, totalNum: {totalNum}, vulNum: {vulNum}")
        if (totalNum > 3 and vulNum / totalNum >= definitions.T) or (totalNum <= 3 and vulNum / totalNum == 1.0):
            print(f"tag: {tag}, totalNum: {totalNum}, vulNum: {vulNum}")


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("-r", "--repo", dest="repo", help="path to the repo", type=str,
                        default="/Users/sunbk201/Desktop/Patch/repo_clone/cache/apache__fdse__tomcat")
    parser.add_argument("-c", "--commit", dest="commit", help="commit to patch", type=str,
                        default="b7e0435d17aba69f16ae9e8a78ad0f1565b552af")
    parser.add_argument("-l", "--log", dest="logpath", help="log file path", type=str,
                        default="patch.log")
    parser.add_argument("--loglevel", dest="loglevel", help="log level", type=int,
                        default=logging.INFO)
    args = parser.parse_args()
    repo_path = args.repo
    commit_id = args.commit
    patch_func = patch_parser(repo_path, commit_id)
    target_parser(repo_path, patch_func)
