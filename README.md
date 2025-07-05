# VERJava

Replication of VERJava. [VERJava](https://ieeexplore.ieee.org/document/9978189/) is a two-stage approach for identifying vulnerable versions of Java Open Source Software (OSS) projects.

# Install

```bash
pip install verjava
```

# Usage

```python
from verjava import verjava

# results will be a list of vulnerability repo tags
vul_tags: list[str] = verjava(
    repo_path="/path/to/your/repo",
    commit_id="your_commit_id", # Patch Commit
)
```

If you want to adjust the parameters, you can do so by passing them as keyword arguments:

```python
vul_tags: list[str] = verjava(
    repo_path="/path/to/your/repo",
    commit_id="your_commit_id",
    tDel=1.0,  # Threshold for deleted lines similarity
    tAdd=0.9,  # Threshold for added lines similarity
    T=0.8,     # Threshold for vulnerability ratio
)
```
