# demo_app 客户端

示例客户端项目，配合 `reproverify` 演示可复现构建验证。

- `build_buggy.py`：**故意埋入** 4 类非确定性（绝对路径、时间戳、随机数、locale）
- `build_fixed.py`：对照构建脚本，遵循 `SOURCE_DATE_EPOCH` 等规范，产物字节级可复现

产物输出到 `dist/`：一个 wheel、一个 zip、一个 tar.gz。
