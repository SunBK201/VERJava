import argparse
import json
import logging

from git import Repo

import definitions
from commit import Commit
from meta import Method, Package


class PatchFunc:
    def __init__(
        self,
        signature: str,
        path: str,
        a_start_line,
        a_end_line,
        b_start_line,
        b_end_line,
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
    ):
        return False
    return True


def patch_parser(repo_path: str, commit_id: str) -> list[PatchFunc]:
    """
    解析 Patch 文件，获取 Patch 中修改过的函数
    """
    patch = Commit(repo_path, commit_id)
    patchFunctions: list[PatchFunc] = []
    for blob in patch.blobs:
        # 只考虑修改过的文件，抛弃 testcase
        if blob.change_type != "C" or "test/" in blob.a_path:
            continue
        a_package = Package(blob.a_blob_content)
        b_package = Package(blob.b_blob_content)
        a_methods: set[Method] = set()
        b_methods: set[Method] = set()
        for clazz in a_package.classes:
            for method in clazz.methods:
                a_methods.add(method)
        for clazz in b_package.classes:
            for method in clazz.methods:
                b_methods.add(method)

        # 获取 Patch 中修改过的函数
        matchPatchFunctions: list[PatchFunc] = []
        for am in a_methods:
            for bm in b_methods:
                if am.signature == bm.signature:
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

        # 获取 Patch 中修改过的函数的修改行
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
    计算 Patch 函数对应的目标函数是否存在漏洞
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
    计算所有存在漏洞的目标版本
    """
    repo = Repo(repo_path)
    vultag = []
    for tag in repo.tags:
        targetFunctions: list[TargetFunc] = []
        targe_commit = repo.commit(tag)

        # 获取目标版本中所有在 Patch 中修改过的函数
        for func in patchFunctions:
            try:
                target_blob = targe_commit.tree[func.file]
            except:
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
        # 计算每一个 Patch 函数对应的目标函数是否存在漏洞
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

        # 计算目标版本中是否存在漏洞
        vulNum = sum(1 for func in targetFunctions if not func.safe)
        if (totalNum > 3 and vulNum / totalNum >= definitions.T) or (
            totalNum <= 3 and vulNum / totalNum == 1.0
        ):
            vultag.append(tag.name)
            print(f"tag: {tag}, totalFunNum: {totalNum}, vulFuncNum: {vulNum}")
        else:
            pass
            # print(f"tag: {tag}, totalFunNum: {totalNum}, vulFuncNum: {vulNum}, safe")
    return vultag


def cli():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-r",
        "--repo",
        dest="repo",
        help="path to the repo",
        type=str,
        default="/Users/sunbk201/Desktop/Patch/repo_clone/cache/netty__fdse__netty",
    )
    parser.add_argument(
        "-c",
        "--commit",
        dest="commit",
        help="commit to patch",
        type=str,
        default="07aa6b5938a8b6ed7a6586e066400e2643897323",
    )
    parser.add_argument(
        "-l",
        "--log",
        dest="logpath",
        help="log file path",
        type=str,
        default="patch.log",
    )
    parser.add_argument(
        "--loglevel", dest="loglevel", help="log level", type=int, default=logging.INFO
    )
    args = parser.parse_args()
    repo_path = args.repo
    commit_id = args.commit
    patch_func: list[PatchFunc] = patch_parser(repo_path, commit_id)
    vultag: list[str] = vulVerCal(repo_path, patch_func)


def validateGroundTruth():
    cve_version = "/Users/sunbk201/Desktop/VulVer/VulnerabilityVersion/1.empirical/cve_analysis.json"
    meta_info = "/Users/sunbk201/Desktop/VulVer/VulnerabilityVersion/0.groundtruth/cve_metainfo.json"
    with open(cve_version) as f:
        version = json.load(f)
    with open(meta_info) as f:
        meta = json.load(f)
    for cve, cve_data in version.items():
        try:
            patch_url = meta[cve]
        except:
            print(f"{cve} not found patch")
            continue
        owner, repo = patch_url.split("/")[3:5]
        print(f"{cve} {owner} {repo}")
        repo_path = (
            f"/Users/sunbk201/Desktop/Patch/repo_clone/cache/{owner}__fdse__{repo}"
        )
        commit_id = patch_url.split("/")[-1]
        try:
            patch_func: list[PatchFunc] = patch_parser(repo_path, commit_id)
            vultag: list[str] = vulVerCal(repo_path, patch_func)
            version[cve]["verjava"] = vultag
        except:
            print(f"{cve} error")
            continue
    cve_version_valid = "/Users/sunbk201/Desktop/VulVer/VulnerabilityVersion/1.empirical/cve_analysis_valid.json"
    with open(cve_version_valid, "w") as f:
        json.dump(version, f, indent=4, ensure_ascii=False)


if __name__ == "__main__":
    # cli()
    validateGroundTruth()
