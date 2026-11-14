# reproverify — 客户端安装包可复现构建验证工具

对“同一份源码 + 锁定依赖”在**两个干净目录**里各构建一次，把 tar / zip / wheel
**解开到文件级**逐个比对，对差异做**非确定性来源自动归因**，并给出可信度结论。

纯 Python 标准库实现，无第三方依赖，离线可跑。

## 它解决什么问题

“我们的安装包支持可复现构建”这句话如果没人验证过，就只是一句口号。常见的坑是：
产物字节不一样，但差异其实来自时间戳、文件顺序、构建机绝对路径、随机 ID、
locale 这类**与代码无关的噪声**；也可能是真正的源码/依赖差异混在里面看不出来。

本工具把这两类东西分开：噪声自动识别并给出消除办法，真正的代码差异单独列出。

## 快速开始

```bash
# 对示例项目跑一次验证（故意埋雷的构建脚本）
python3 -m reproverify \
  --source examples/demo_app \
  --build-cmd "python3 build_buggy.py" \
  --vary-env

# 对照：修复后的构建脚本，应当字节级一致、满分
python3 -m reproverify \
  --source examples/demo_app \
  --build-cmd "python3 build_fixed.py" \
  --vary-env
```

验证真实项目时，`--build-cmd` 里放你自己的构建命令，例如：

```bash
python3 -m reproverify \
  --source /path/to/client \
  --build-cmd 'python -m venv .venv && . .venv/bin/activate && pip install -r requirements.lock && python build.py' \
  --dist-subdir dist \
  --vary-env
```

## 工作流程

```
源码树 ──复制──> 干净目录 A（受控环境 A）──> 构建 ──> dist(A)
      └─复制──> 干净目录 B（受控环境 B）──> 构建 ──> dist(B)
                                                  │
              产物按相对路径配对，sha256 比对 <───┘
                          │
        字节一致？──是──> 该产物可复现
              │否
   tar/zip/wheel 解包到成员级（内存中，tar 做路径穿越检查）
              │
   归档级：成员顺序 / 成员集合 / gzip mtime
   成员级：mtime / uid/gid/属主 / 权限位 / 文件内容
              │
   内容差异走规则链归因（见下），解释不了的判为真实代码差异
```

### 受控构建环境

两侧默认使用一致的干净环境，唯一天然差异是工作目录绝对路径（这正是检测路径泄漏
所必需的）：

| 变量 | 值 | 目的 |
|---|---|---|
| `LC_ALL` / `LANG` | `C.UTF-8` | 固定 locale |
| `TZ` | `UTC` | 固定时区 |
| `PYTHONHASHSEED` | `0` | 固定哈希随机化 |
| `PYTHONDONTWRITEBYTECODE` | `1` | 不写 `.pyc` |
| `SOURCE_DATE_EPOCH` | 固定 epoch | 统一时间戳来源 |

`--vary-env` 会让 B 侧切换到 `en_US.UTF-8` / `America/New_York` 并换一套 tar 身份，
专门探测 locale/时区/属主类非确定性。

## 归因规则（规则链）

每条规则是一个**归一化器**：把它认识的非确定 token 替换成占位符，两边文本经过
同一条链后若一致，则差异全部可归因；仍不一致的部分判为真实代码差异。

| 类别 | 识别形态 | 消除办法（摘要） |
|---|---|---|
| 绝对路径 | 构建根路径、通用 POSIX/Windows 路径、`file://` URI | 只记相对路径、`-ffile-prefix-map` |
| 时间戳 | ISO-8601、RFC2822、斜杠/点分日期、epoch 秒/毫秒（带构建时间窗口校验） | 遵循 `SOURCE_DATE_EPOCH`、固定 zip/tar/gzip 时间 |
| locale/时区 | 分组数字、欧陆小数点、货币、locale 标签、时区缩写、NFC/NFD | 固定 `LC_ALL=C`、`TZ=UTC`、显式格式化 |
| 随机数 | UUID、指针地址、hex 摘要、URL-safe base64、tmp 名、高熵 token、随机字节 | 用内容哈希派生 ID，不要用 uuid4/random |
| 成员顺序 | 归档成员物理顺序不同而集合相同 | 打包前按名排序 |
| 属主/权限 | tar 的 uid/gid/uname、mode | tar filter 统一中性值 |
| gzip mtime | gzip 头 mtime | `GzipFile(mtime=...)` 固定 |
| 成员缺失 | 两侧成员集合不同 | 显式化输入清单 |
| **真实代码差异** | 上述规则归一后仍不一致，附 unified diff | 人工核查源码与依赖锁定 |

规则只做形态识别 + 时间窗口校验，不靠文件名猜测；高置信随机模式（UUID 等）在链首
先跑并以占位符保护，避免被后续规则切碎。

## 可信度结论

| 结论 | 含义 | 退出码 |
|---|---|---|
| `reproducible` | 所有产物字节级一致 | 0 |
| `deterministic-with-fixes` | 差异全部可归因于已知非确定源，按建议修复即可复现 | 0 |
| `non-reproducible` | 存在真实代码差异或无法归因的差异，**不可宣称可复现** | 1 |
| `error` | 构建失败或无产物 | 2 |

同时给出 0–100 评分：真实代码差异/无法归因扣分最重，可修复的非确定源扣分较轻，
同一类别在多个产物重复出现只象征性扣分。

## 命令参数

```
--source        源码目录（会被完整复制到两个干净目录）
--build-cmd     在源码目录执行的构建命令（shell）
--dist-subdir   产物子目录，默认 dist
--workdir       工作目录，默认系统临时目录
--epoch         注入的 SOURCE_DATE_EPOCH，默认固定值
--vary-env      B 侧切换 locale/时区/tar 身份做探测
--timeout       单侧构建超时秒数，默认 600
--keep          保留工作目录便于事后检查
--format        text（默认）/ json / markdown
--output        报告输出文件，默认 stdout
```

## 示例项目埋的雷

`examples/demo_app/build_buggy.py` 故意包含四类非确定性：

1. **绝对路径** — `BUILD_METADATA.json` 写入构建目录绝对路径
2. **时间戳** — 墙钟时间（ISO/RFC/epoch）、归档 mtime、gzip mtime
3. **随机数** — `uuid4` 生成 build_id、`os.urandom` 生成 nonce、`random.shuffle` 打乱顺序
4. **locale** — `setlocale(LC_ALL, "")` 跟随环境，货币/数字/时间格式随 locale/时区变化

`build_fixed.py` 是对照实现，全部按规范消除，两次构建字节级一致。

## 运行测试

```bash
python3 -I -m unittest discover -s tests -t .
```

37 个测试覆盖：规则引擎（含一个 base64 边界的 flaky 回归）、归档解析（含 tar 路径
穿越防护）、端到端双构建、真实代码注入检出、构建失败退出码。

## 安全说明

- tar 成员做路径穿越检查，拒绝绝对路径与 `..` 成员；
- 归档在内存中读取，不在不受信任目录落盘；
- 构建环境变量走白名单透传，宿主的杂散变量不会泄漏进构建。
