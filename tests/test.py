from verjava import verjava

vul_tags: list[str] = verjava(
    repo_path="/path/to/your/repo",
    commit_id="your_commit_id",
    tDel=1.0,
    tAdd=0.9,
    T=0.8,
)
