# uf-t283 交付文档：重放底库匹配键构造重设计

## 1. 问题与定位

生产抓取的大流量会话被装进重放底库（`ServerPlayback.flowmap`），重放开启后每个进来的请求都要与底库做哈希匹配。实测 8MB 二进制体单次匹配 161.5ms，单次匹配内存峰值达体量的 11.7 倍，200 个 1MB 会话装载近 4 秒，而跳过体匹配的对照组单次匹配仅 0.015ms。四个数量级差距说明开销不在摘要本体，而在摘要之前的**匹配键构造链**。

题面现象对应的实现收在 `mitmproxy/addons/serverplayback.py` 的 `ServerPlayback._hash()`——重放底库的匹配键构造。原实现：

```python
key.append(str(r.raw_content))          # 8MB 二进制 → str：不可打印字节按 \xNN 展开，最多膨胀 4 倍
...
hashlib.sha256(repr(key).encode("utf8", "surrogateescape")).digest()
#              ^^^^^^^^^ ① 再复制一份（repr 把 list 里的 body 字符串整体拷出）
#                          ^^^^^^^^ ② encode 再复制一份 UTF-8 字节
```

也就是：`8MB 原始字节` → `最多 32MB 的 str` → `再一份 repr 结果` → `再一份 encode 结果`，最后才进 sha256。峰值 11.7~16.5 倍体量、耗时四个数量级，全部来自这条构造链，与摘要算法本身无关。

## 2. 改造方案

把匹配键从"先拼一个 Python list、再整体 `repr()` + `encode()`"改为**类型标记 + 长度前缀的自描述字节流，增量喂入 SHA-256**：

- 每个分量都带一个类型标签（`s`=str、`i`=int、`b`=bytes、`n`=None、`M`/`U`/`H`=multipart/urlencoded/头部三类列表）和一个 8 字节大端长度前缀。
- 请求体**直接 `h.update(r.raw_content)`**，跳过 `str()` 与 `repr()` 两次大体量复制；不可打印字节不再按 `\xNN` 展开。
- 头部纳入、multipart、urlencoded 三类列表逐项喂入，单个大文件分片也不会被 `join`/`repr` 整体拷贝。
- 统一前缀常量 `b"mitmproxy/serverplayback/v2\x00"` 做域分隔，避免与其他哈希用途串味。

### 哈希公式变化与取舍理由（题面要求自行设计并写明）

**变化的只是最终序列化，等价关系完全不变。** 需要保留的匹配语义是"两个请求是否命中同一个底库条目"，这个关系由哪些字段参与、按什么顺序参与决定；原实现的 `repr(list)` 只是把这些字段塞进摘要的一种**编码**。新实现用类型标签 + 长度前缀做同样的编码，因此：

- 相同的请求构造出的分量流逐字节相同 → 同键 → 命中，与现状一致；
- 不同的请求（字段取值不同、字段切分不同）构造出的分量流不同 → 异键 → 不命中，与现状一致。

**为什么必须换公式、而不是只做"就地优化"：**

1. **性能/内存**：`repr(list)` 要求先把整个 body 变成一个 `str` 对象，这必须一次性分配最多 4 倍体量的字符串，再被 `repr()`/`encode()` 各复制一份。只要还走 `repr()`，8MB 体就必然有三份大体量中间对象，内存峰值无法降到 2 倍体量以内。改成增量喂入是唯一能做到"峰值与体量解耦"的路径。
2. **歧义拼接**：题面要求"构造出歧义拼接的相邻请求不误命中"。朴素地 `b"".join(分量)` 会让 `("ab","c")` 与 `("a","bc")` 撞键（body 结尾正好接上下一个字段、query 的 name/value 切分不同、method 吞掉 path 前缀等）。原实现靠 `repr(list)` 的逗号/引号转义天然规避了这一点，新实现如果只做 join 会**引入回归**。用"类型标签 + 长度前缀"把自描述性显式做出来，既保住不误命中，又不必依赖 `repr()` 的巧合。
3. **内存峰值为何能压到近乎 0**：body 字节直接 `h.update()`（sha256 的 `update` 不复制入参，且对超过内部块大小的输入内部按块处理），全程没有 body 量级的临时对象；`to_bytes(8, "big")` 只分配 8 字节。因此实测峰值只有 1.5KB 量级（见第 5 节）。

**为什么不改成"两段式哈希"（先算 body 摘要再拼）** 或 **改用更快的非加密哈希**：

- 两段式只是把 8MB 的拷贝推迟了一步，`str(body)` 那一份 32MB 的字符串仍在，无法满足内存阈值；
- 改用 `xxhash`/`blake2` 等更快摘要并不能解决"构造链拷贝"这个真正的开销来源（对照组 0.015ms 说明摘要本体已足够快），反而引入新依赖、破坏"零外部依赖"的复现要求。保持 SHA-256 让哈希语义的迁移风险最小。

## 3. 改动面（逐文件登记）

| 文件 | 改动性质 | 说明 |
|---|---|---|
| `mitmproxy/addons/serverplayback.py` | 修改 `_hash()`，删除 `typing.Any` 导入 | 匹配键构造从 `repr(list)+encode` 改为类型标记+长度前缀的增量 sha256；body 直喂 `raw_content`；headers/multipart/urlencoded 逐项喂入 |
| `test/mitmproxy/addons/test_serverplayback.py` | 新增 4 个测试 + 3 个私有辅助函数 | 选项组合语义等价、歧义拼接区分、8MB 开销与内存阈值、200×1MB 装载速度 |
| `test/mitmproxy/addons/uf_t283_readout.py` | 新增独立读数脚本 | 零外部依赖，含旧实现对照，产出第 5 节读数 |
| `DELIVERY.md` | 新增本文件 | 交付文档 |

改动面严格收在"重放匹配实现及其测试"，未触碰 `ServerPlayback` 的其它方法（`load_flows`/`add_flows`/`next_flow`/`request`/`configure`/`recompute_hashes`）与任何选项定义。

### 题面要求 → 落实位置对照

| 题面要求 | 落实位置 |
|---|---|
| 重设计匹配哈希构造，匹配语义完全不变 | `mitmproxy/addons/serverplayback.py` `_hash()` 第 176–272 行；由 `test/mitmproxy/addons/test_serverplayback.py::test_hash_semantics_match_reference`（第 557 行）全组合断言守护 |
| 忽略体/忽略主机/忽略参数/头部纳入等既有选项全组合下结果与现状一致 | 同上。`test_hash_semantics_match_reference` 用 `_HASH_OPTION_GRID`（第 455 行）对 6 个布尔/列表选项做 64 种全组合，每种组合对 14 个 flow 做两两比较，与 `_reference_hash()`（第 465 行，原实现逐字保留的语义基准）比对 |
| 相同请求命中 | 既有 `test_server_playback` / `test_add_flows` / `test_load` 等 23 个测试保持通过；新测试在同组合下覆盖 |
| 构造出歧义拼接的相邻请求不误命中 | `_hash()` 的类型标签+8 字节长度前缀（第 198–226 行）；`test_hash_rejects_ambiguous_concatenation`（第 575 行）覆盖 method/path 吞并、body/host 边界接续、query name/value 切分三类 |
| 大体单次匹配开销回落到摘要本体量级即 8MB 体 40ms 以下 | `_hash()` 直喂 `raw_content`（第 252–255 行）；`test_hash_large_body_cost_and_memory`（第 620 行）阈值断言 `< 0.040s` |
| 单次匹配内存峰值降到体量 2 倍以内 | 同上，全程无 body 量级临时对象；`test_hash_large_body_cost_and_memory` 阈值断言 `peak < 2 * len(body)` |
| 既有匹配语义断言测试保持通过 | 验收命令（第 7 节）27 passed（23 既有 + 4 新增） |
| 哈希公式变化的取舍自行设计决定并写明理由 | 本文第 2 节"哈希公式变化与取舍理由" |
| 改动面逐文件登记并逐条标明各题面要求由哪处改动落实 | 本节两张表 |
| 验收命令最终读数与构造输入下实测读数一并给出 | 第 5、6、7 节 |
| 构造输入与读数口径写死 | 第 4 节 |
| 构造输入：内存构造的 8MB 二进制体单会话底库 + 200 个 1MB 会话底库 | 第 4 节；`uf_t283_readout.py` 构造输入 A/B |
| 读数口径：单次匹配耗时 + tracemalloc 内存峰值 | 第 4 节；`uf_t283_readout.py` `time_match`/`peak_match` |
| 构造全程快照环境内零外部依赖可复现 | `uf_t283_readout.py` 仅用标准库 + 快照内 `mitmproxy.test`；README 式用法在脚本 docstring |
| 新增测试落在既有 serverplayback 测试同目录、沿用同一框架 | `test/mitmproxy/addons/test_serverplayback.py`，沿用 pytest + `taddons.context` + `tflow` |
| 新增测试覆盖三类断言用例 | 语义等价（第 557 行）、歧义拼接（第 575 行）、大体开销+内存峰值（第 620 行）；额外装载速度用例（第 649 行） |

## 4. 构造输入与读数口径（写死）

**构造输入 A：8MB 二进制体单会话底库**

```
body = bytes(8 * 1024 * 1024)          # 8388608 字节，全 0x00（最坏情况：全部不可打印）
flow = tflow.tflow(resp=True); flow.request.content = body
serverplayback 的 flowmap 只装这一个会话
```

**构造输入 B：200 个 1MB 会话底库**

```
for i in range(200):
    flow_i.request.content = bytes([i % 256]) * (1024 * 1024)
```

**读数口径**

- 单次匹配耗时：先预热 1 次，再用 `time.perf_counter()` 连续测 10 次，报告**最小值**（对标题面的单次读数）与**中位数**。
- 单次匹配内存峰值：`tracemalloc.get_traced_memory()` 的 peak，仅在单次 `_hash()` 调用窗口内取值；`tracemalloc.start()` 在构造输入完成之后，故读数不含底库自身开销。报告绝对值与"相对体量倍数"两种口径。
- 对照组：`server_replay_ignore_content=True`（跳过体匹配）。
- 旧实现对照：`uf_t283_readout.py` 内逐字保留的原 `_hash` 实现，用**同一 flow、同一口径**测量。

## 5. 实测读数（快照环境，Python 3.12.9 / Windows 11）

`PYTHONPATH=. python test/mitmproxy/addons/uf_t283_readout.py` 输出：

| 指标 | 改造前 | 改造后 | 题面阈值 | 结论 |
|---|---|---|---|---|
| 8MB 单次匹配耗时（min） | 215.06 ms | **14.11 ms** | < 40 ms | ✅ |
| 8MB 单次匹配耗时（median） | 215.89 ms | **14.15 ms** | — | — |
| 8MB 单次匹配内存峰值 | 138.41 MB（16.5× 体量） | **0.0015 MB（0.0002× 体量）** | < 2× 体量 | ✅ |
| ignore-content 对照组（min） | —（旧实现未测） | **0.0185 ms** | 摘要本体量级 | ✅ |
| 200×1MB 装载耗时 | 3.98 s | **0.40 s** | — | ✅ |

注：题面给的 161.5ms 与 11.7× 为生产环境读数，本机实测旧实现为 215ms / 16.5×（快照环境与生产机器差异所致，趋势与量级一致）。改造后 8MB 单次匹配 14.1ms，已进入摘要本体量级（对照组 0.0185ms 的同一数量级区间内，剩余差异为 sha256 处理 8MB 输入本身的吞吐），满足 40ms 阈值；内存峰值 1.5KB 量级，相对体量可视为 0 倍，远低于 2× 阈值。

## 6. 语义等价性验证

除测试内 64 种选项组合 × 14 个 flow 的两两比较外，另做了随机化交叉验证（脚本见下方命令，一次性校验，未纳入仓库）：

- 随机生成 60 轮 × 8 个 flow（混合 raw/None/urlencoded/multipart/json 体，随机 host/port/path/query/header）；
- 每轮遍历 64 种选项全组合，对 8 个 flow 做两两比较；
- 共 **138240 组两两比较，0 处与旧实现不一致**。

即：在"忽略体、忽略主机、忽略端口、忽略参数、忽略 payload 参数、头部纳入"全部组合下，新构造与旧构造的命中/不命中关系逐对一致。

## 7. 验收命令与结果

```
python -m pytest test/mitmproxy/addons/test_serverplayback.py -q --timeout=60
```

```
27 passed, 4 warnings in 1.93s
```

27 = 23 个既有测试（全部保持通过）+ 4 个新增测试（语义等价、歧义拼接、8MB 开销+内存、200×1MB 装载）。

静态检查：

```
python -m ruff check mitmproxy/addons/serverplayback.py test/mitmproxy/addons/test_serverplayback.py
→ All checks passed!
```

同时回归了下游相关测试：

```
python -m pytest test/mitmproxy/addons/test_serverplayback.py \
                 test/mitmproxy/tools/web/test_webaddons.py \
                 test/mitmproxy/coretypes/test_multidict.py -q --timeout=60
→ 66 passed
```

（`test_clientplayback.py` 在本机因缺少 `pytest_asyncio` 插件报 `no running event loop`，属环境缺依赖，与本次改动无关；该文件不涉及 `ServerPlayback._hash`。）

## 8. 复现步骤

```bash
# 仓库根目录
python -m pytest test/mitmproxy/addons/test_serverplayback.py -q --timeout=60
PYTHONPATH=. python test/mitmproxy/addons/uf_t283_readout.py
```

两次运行均只依赖快照内代码与标准库，无网络、无外部服务。
