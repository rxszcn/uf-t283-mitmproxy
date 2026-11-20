"""uf-t283 验收读数脚本（零外部依赖，快照环境内可直接复现）。

用法（仓库根目录）：
    PYTHONPATH=. python test/mitmproxy/addons/uf_t283_readout.py

构造输入（写死口径，见 DELIVERY.md）：
  A. 8MB 二进制体单会话底库
       body = bytes(8 * 1024 * 1024)，单 flow，serverplayback 只装这一个会话。
  B. 200 个 1MB 会话底库
       第 i 个 flow 的 body = bytes([i % 256]) * (1024 * 1024)，共 200 个。

读数口径（写死口径，见 DELIVERY.md）：
  单次匹配耗时：预热 1 次后，用 time.perf_counter() 连续测 10 次的 **最小值** 与 **中位数**。
  单次匹配内存峰值：tracemalloc.get_traced_memory() 的 peak，仅在单次 _hash() 的调用窗口内取值。
                   构造输入全部在 tracemalloc.start() 之前完成，故读数不含底库自身开销。
  对照组：server_replay_ignore_content=True（跳过体匹配）。
  旧实现：脚本内保留的原 _hash 实现（仅最终序列化不同），用同一 flow 与同一口径测量。
"""

import hashlib
import statistics
import time
import tracemalloc
import urllib.parse

from mitmproxy import ctx
from mitmproxy.addons import serverplayback
from mitmproxy.test import taddons
from mitmproxy.test import tflow

MB = 1024 * 1024
ROUNDS = 10


def old_hash(flow):
    """改造前的匹配键构造，语义基准。"""
    r = flow.request
    _, _, path, _, query, _ = urllib.parse.urlparse(r.url)
    queries = urllib.parse.parse_qsl(query, keep_blank_values=True)

    key = [str(r.scheme), str(r.method), str(path)]
    if not ctx.options.server_replay_ignore_content:
        if ctx.options.server_replay_ignore_payload_params and r.multipart_form:
            key.extend(
                (k, v)
                for k, v in r.multipart_form.items(multi=True)
                if k.decode(errors="replace")
                not in ctx.options.server_replay_ignore_payload_params
            )
        elif ctx.options.server_replay_ignore_payload_params and r.urlencoded_form:
            key.extend(
                (k, v)
                for k, v in r.urlencoded_form.items(multi=True)
                if k not in ctx.options.server_replay_ignore_payload_params
            )
        else:
            key.append(str(r.raw_content))
    if not ctx.options.server_replay_ignore_host:
        key.append(r.pretty_host)
    if not ctx.options.server_replay_ignore_port:
        key.append(r.port)

    filtered = [p for p in queries if p[0] not in (ctx.options.server_replay_ignore_params or [])]
    for p in filtered:
        key.append(p[0])
        key.append(p[1])

    if ctx.options.server_replay_use_headers:
        key.append([(i, r.headers.get(i)) for i in ctx.options.server_replay_use_headers])
    return hashlib.sha256(repr(key).encode("utf8", "surrogateescape")).digest()


def time_match(fn, flow):
    fn(flow)  # 预热
    samples = []
    for _ in range(ROUNDS):
        start = time.perf_counter()
        fn(flow)
        samples.append((time.perf_counter() - start) * 1000)
    return min(samples), statistics.median(samples)


def peak_match(fn, flow):
    tracemalloc.start()
    try:
        tracemalloc.reset_peak()
        fn(flow)
        return tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()


def main():
    sp = serverplayback.ServerPlayback()
    with taddons.context(sp) as tctx:
        tctx.configure(sp)

        # 构造输入 A：8MB 二进制体单会话底库
        body = bytes(8 * MB)
        flow_8mb = tflow.tflow(resp=True)
        flow_8mb.request.content = body

        old_min, old_med = time_match(old_hash, flow_8mb)
        new_min, new_med = time_match(sp._hash, flow_8mb)
        old_peak = peak_match(old_hash, flow_8mb)
        new_peak = peak_match(sp._hash, flow_8mb)

        tctx.configure(sp, server_replay_ignore_content=True)
        ctrl_min, ctrl_med = time_match(sp._hash, flow_8mb)
        tctx.configure(sp, server_replay_ignore_content=False)

        print("构造输入 A：8MB 二进制体单会话底库 (body = %d 字节)" % len(body))
        print("  单次匹配耗时 old  min %.2f ms  median %.2f ms" % (old_min, old_med))
        print("  单次匹配耗时 new  min %.2f ms  median %.2f ms" % (new_min, new_med))
        print("  对照组 ignore-content  min %.4f ms  median %.4f ms" % (ctrl_min, ctrl_med))
        print(
            "  单次匹配内存峰值 old  %.2f MB (%.1fx body)"
            % (old_peak / 1e6, old_peak / len(body))
        )
        print(
            "  单次匹配内存峰值 new  %.4f MB (%.4fx body)"
            % (new_peak / 1e6, new_peak / len(body))
        )

        # 构造输入 B：200 个 1MB 会话底库
        flows = []
        for i in range(200):
            f = tflow.tflow(resp=True)
            f.request.content = bytes([i % 256]) * MB
            flows.append(f)

        start = time.perf_counter()
        sp.load_flows(flows)
        load_new = time.perf_counter() - start

        start = time.perf_counter()
        old_map = {}
        for f in flows:
            old_map.setdefault(old_hash(f), []).append(f)
        load_old = time.perf_counter() - start

        print()
        print("构造输入 B：200 个 1MB 会话底库")
        print("  装载耗时 old  %.2f s" % load_old)
        print("  装载耗时 new  %.2f s  count=%d" % (load_new, sp.count()))


if __name__ == "__main__":
    main()
