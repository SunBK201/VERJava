import argparse
import json
import logging

from git import Repo

from . import definitions
from .commit import Commit
from .meta import Method, Package


class PatchFunc:
    def __init__(
        self,
        signature: str,
        path: str,
        a_start_line: int,
        a_end_line: int,
        b_start_line: int,
        b_end_line: int,
    ):
        self.signature = signature
        self.file = path
        self.a_start_line = a_start_line
        self.a_end_line = a_end_line
        self.b_start_line = b_start_line
        self.b_end_line = b_end_line
        self.addline = set()
        self.delline = set()


class TargetFunc:
    def __init__(
        self, signature: str, source_code: str, start_line: int, end_line: int
    ):
        self.signature = signature
        self.line = set()
        self.safe = True

        source_code_lines = source_code.split("\n")
        for line in source_code_lines:
            if not isValidCodeLine(line):
                continue
            self.line.add(line.strip().replace(" ", ""))


def isValidCodeLine(code: str) -> bool:
    code = code.strip()
    if (
        code == ""
        or code.startswith("//")
        or code.startswith("/*")
        or code.startswith("*/")
        or code == "{"
        or code == "}"
        or code == ";"
        or code == "("
        or code == ")"
        or code == "["
        or code == "]"
        or code == "/*"
        or code == "*/"
    ):
        return False
    return True


def parsePatch(repo_path: str, commit_id: str) -> list[PatchFunc]:
    """
    Parse the patch file and get the functions modified in the patch
    """
    patch = Commit(repo_path, commit_id)
    patchFunctions: list[PatchFunc] = []
    for blob in patch.blobs:
        # Only consider modified files, discard testcases
        if blob.change_type != "C" or (
            blob.a_path is not None and "test/" in blob.a_path
        ):
            continue
        a_package = Package(
            blob.a_blob_content if blob.a_blob_content is not None else ""
        )
        b_package = Package(
            blob.b_blob_content if blob.b_blob_content is not None else ""
        )
        a_methods: set[Method] = set()
        b_methods: set[Method] = set()
        for clazz in a_package.classes:
            for method in clazz.methods:
                a_methods.add(method)
        for clazz in b_package.classes:
            for method in clazz.methods:
                b_methods.add(method)

        # Get the functions modified in the Patch
        matchPatchFunctions: list[PatchFunc] = []
        for am in a_methods:
            for bm in b_methods:
                if am.signature == bm.signature:
                    if blob.b_path is None:
                        continue
                    matchPatchFunctions.append(
                        PatchFunc(
                            am.signature,
                            blob.b_path,
                            am.start_line,
                            am.end_line,
                            bm.start_line,
                            bm.end_line,
                        )
                    )
                    break

        # Get the modified lines of the functions modified in the Patch
        for hunk in blob.hunks:
            for line, code in hunk.added_lines.items():
                if not isValidCodeLine(code):
                    continue
                for matchfunc in matchPatchFunctions:
                    if matchfunc.b_start_line <= line <= matchfunc.b_end_line:
                        matchfunc.addline.add(code.strip().replace(" ", ""))
            for line, code in hunk.deleted_lines.items():
                if not isValidCodeLine(code):
                    continue
                for matchfunc in matchPatchFunctions:
                    if matchfunc.a_start_line <= line <= matchfunc.a_end_line:
                        matchfunc.delline.add(code.strip().replace(" ", ""))

        for matchfunc in matchPatchFunctions:
            if len(matchfunc.addline) != 0 or len(matchfunc.delline) != 0:
                patchFunctions.append(matchfunc)

    return patchFunctions


def vulFuncCal(patchFunction: PatchFunc, targetFunction: TargetFunc) -> bool:
    """
    Calculate whether the target function corresponding to the Patch function is vulnerable
    """
    targetFuncLineSet = targetFunction.line
    delLineSet_n = len(patchFunction.delline)
    addLineSet_n = len(patchFunction.addline)
    delSim = 0
    addSim = 0
    if delLineSet_n != 0:
        delSim = len(patchFunction.delline & targetFuncLineSet) / delLineSet_n
    if addLineSet_n != 0:
        addSim = len(patchFunction.addline & targetFuncLineSet) / addLineSet_n
    if delLineSet_n != 0 and addLineSet_n != 0:
        if delSim >= definitions.tDel and addSim <= definitions.tAdd:
            targetFunction.safe = False
    elif addLineSet_n == 0:
        if delSim >= definitions.tDel:
            targetFunction.safe = False
    elif delLineSet_n == 0:
        if addSim <= definitions.tAdd:
            targetFunction.safe = False
    else:
        targetFunction.safe = True
    return targetFunction.safe


def vulVerCal(repo_path: str, patchFunctions: list[PatchFunc]) -> list[str]:
    """
    Calculate all vulnerable target versions
    """
    repo = Repo(repo_path)
    vultag = []
    for tag in repo.tags:
        targetFunctions: list[TargetFunc] = []
        targe_commit = repo.commit(tag.name)

        # Get all functions in the target version that have been modified in the Patch
        for func in patchFunctions:
            try:
                target_blob = targe_commit.tree[func.file]
            except Exception:
                continue
            target_package = Package(target_blob.data_stream.read().decode())
            for clazz in target_package.classes:
                for method in clazz.methods:
                    if method.signature == func.signature:
                        targetFunctions.append(
                            TargetFunc(
                                method.signature,
                                method.body_source_code,
                                method.start_line,
                                method.end_line,
                            )
                        )

        totalNum = len(patchFunctions)
        # Calculate whether each target function corresponding to the Patch function is vulnerable
        for patchfunc in patchFunctions:
            targetFunc = next(
                (tf for tf in targetFunctions if tf.signature == patchfunc.signature),
                None,
            )
            if targetFunc is None:
                totalNum -= 1
                continue
            vulFuncCal(patchfunc, targetFunc)

        if totalNum == 0:
            continue

        # Calculate whether there are vulnerabilities in the target version
        vulNum = sum(1 for func in targetFunctions if not func.safe)
        if (totalNum > 3 and vulNum / totalNum >= definitions.T) or (
            totalNum <= 3 and vulNum / totalNum == 1.0
        ):
            vultag.append(tag.name)
            logging.debug(f"tag: {tag}, totalFunNum: {totalNum}, vulFuncNum: {vulNum}")
        else:
            pass
            # logging.debug(f"tag: {tag}, totalFunNum: {totalNum}, vulFuncNum: {vulNum}, safe")
    return vultag


def verjava(
    repo_path: str,
    commit_id: str,
    tDel: float = definitions.tDel,
    tAdd: float = definitions.tAdd,
    T: float = definitions.T,
) -> list[str]:
    """
    Main function to calculate vulnerable versions

    :param repo_path: Path to the repository
    :param commit_id: Commit ID to patch
    :param tDel: Threshold for deleted lines similarity
    :param tAdd: Threshold for added lines similarity
    :param T: Threshold for vulnerable function ratio

    :return: List of vulnerable versions (tags)
    """
    definitions.tDel = tDel
    definitions.tAdd = tAdd
    definitions.T = T
    patch_func: list[PatchFunc] = parsePatch(repo_path, commit_id)
    vultag: list[str] = vulVerCal(repo_path, patch_func)
    return vultag


def cli():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-r",
        "--repo",
        dest="repo",
        required=True,
        help="path to the repo",
        type=str,
    )
    parser.add_argument(
        "-c",
        "--commit",
        dest="commit",
        required=True,
        help="commit to patch",
        type=str,
    )
    # tDel: threshold for deleted lines similarity
    parser.add_argument(
        "--tDel",
        dest="tDel",
        help="threshold for deleted lines similarity",
        type=float,
        default=definitions.tDel,
    )
    # tAdd: threshold for added lines similarity
    parser.add_argument(
        "--tAdd",
        dest="tAdd",
        help="threshold for added lines similarity",
        type=float,
        default=definitions.tAdd,
    )
    # T: threshold for vulnerable function ratio
    parser.add_argument(
        "--T",
        dest="T",
        help="threshold for vulnerable function ratio",
        type=float,
        default=definitions.T,
    )
    # results output mode: stdout or json
    parser.add_argument(
        "-o",
        "--output",
        dest="output",
        help="output mode, stdout or json",
        type=str,
        default="stdout",
    )
    parser.add_argument(
        "-l",
        "--log",
        dest="logpath",
        help="log file path",
        type=str,
        default="verjava.log",
    )
    parser.add_argument(
        "--loglevel", dest="loglevel", help="log level", type=int, default=logging.DEBUG
    )
    args = parser.parse_args()
    repo_path = args.repo
    commit_id = args.commit
    definitions.tDel = args.tDel
    definitions.tAdd = args.tAdd
    definitions.T = args.T
    logging.basicConfig(
        filename=args.logpath,
        level=args.loglevel,
        format="%(asctime)s - %(levelname)s - %(message)s",
    )
    vultag: list[str] = verjava(repo_path, commit_id)
    if args.output == "stdout":
        print("Vulnerable versions (tags):")
        for tag in vultag:
            print(tag)
    elif args.output == "json":
        with open("verjava_results.json", "w") as f:
            json.dump(vultag, f, indent=4)
    else:
        logging.error("Invalid output mode. Use 'stdout' or 'json'.")


if __name__ == "__main__":
    cli()
