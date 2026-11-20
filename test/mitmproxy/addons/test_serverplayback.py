import itertools
import time
import tracemalloc
import urllib

import pytest

import mitmproxy.test.tutils
from mitmproxy import exceptions
from mitmproxy import io
from mitmproxy.addons import serverplayback
from mitmproxy.test import taddons
from mitmproxy.test import tflow


def tdump(path, flows):
    with open(path, "wb") as f:
        w = io.FlowWriter(f)
        for i in flows:
            w.add(i)


def test_load_file(tmpdir):
    s = serverplayback.ServerPlayback()
    with taddons.context(s):
        fpath = str(tmpdir.join("flows"))
        tdump(fpath, [tflow.tflow(resp=True)])
        s.load_file(fpath)
        assert s.flowmap
        with pytest.raises(exceptions.CommandError):
            s.load_file("/nonexistent")


def test_config(tmpdir):
    s = serverplayback.ServerPlayback()
    with taddons.context(s) as tctx:
        fpath = str(tmpdir.join("flows"))
        tdump(fpath, [tflow.tflow(resp=True)])
        tctx.configure(s, server_replay=[fpath])
        s.configured = False
        with pytest.raises(exceptions.OptionsError):
            tctx.configure(s, server_replay=[str(tmpdir)])


def test_server_playback():
    sp = serverplayback.ServerPlayback()
    with taddons.context(sp) as tctx:
        tctx.configure(sp)
        f = tflow.tflow(resp=True)

        assert not sp.flowmap

        sp.load_flows([f])
        assert sp.flowmap
        assert sp.next_flow(f)
        assert not sp.flowmap

        sp.load_flows([f])
        assert sp.flowmap
        sp.clear()
        assert not sp.flowmap


def test_add_flows():
    sp = serverplayback.ServerPlayback()
    with taddons.context(sp) as tctx:
        tctx.configure(sp)
        f1 = tflow.tflow(resp=True)
        f2 = tflow.tflow(resp=True)

        sp.load_flows([f1])
        sp.add_flows([f2])

        assert sp.next_flow(f1)
        assert sp.flowmap
        assert sp.next_flow(f2)
        assert not sp.flowmap

        sp.add_flows([f1])
        assert sp.flowmap
        assert sp.next_flow(f1)
        assert not sp.flowmap


def test_ignore_host():
    sp = serverplayback.ServerPlayback()
    with taddons.context(sp) as tctx:
        tctx.configure(sp, server_replay_ignore_host=True)

        r = tflow.tflow(resp=True)
        r2 = tflow.tflow(resp=True)

        r.request.host = "address"
        r2.request.host = "address"
        assert sp._hash(r) == sp._hash(r2)
        r2.request.host = "wrong_address"
        assert sp._hash(r) == sp._hash(r2)


def test_ignore_content():
    s = serverplayback.ServerPlayback()
    with taddons.context(s) as tctx:
        tctx.configure(s, server_replay_ignore_content=False)

        r = tflow.tflow(resp=True)
        r2 = tflow.tflow(resp=True)

        r.request.content = b"foo"
        r2.request.content = b"foo"
        assert s._hash(r) == s._hash(r2)
        r2.request.content = b"bar"
        assert not s._hash(r) == s._hash(r2)

        tctx.configure(s, server_replay_ignore_content=True)
        r = tflow.tflow(resp=True)
        r2 = tflow.tflow(resp=True)
        r.request.content = b"foo"
        r2.request.content = b"foo"
        assert s._hash(r) == s._hash(r2)
        r2.request.content = b"bar"
        assert s._hash(r) == s._hash(r2)
        r2.request.content = b""
        assert s._hash(r) == s._hash(r2)
        r2.request.content = None
        assert s._hash(r) == s._hash(r2)


def test_ignore_content_wins_over_params():
    s = serverplayback.ServerPlayback()
    with taddons.context(s) as tctx:
        tctx.configure(
            s,
            server_replay_ignore_content=True,
            server_replay_ignore_payload_params=["param1", "param2"],
        )

        # NOTE: parameters are mutually exclusive in options
        r = tflow.tflow(resp=True)
        r.request.headers["Content-Type"] = "application/x-www-form-urlencoded"
        r.request.content = b"paramx=y"

        r2 = tflow.tflow(resp=True)
        r2.request.headers["Content-Type"] = "application/x-www-form-urlencoded"
        r2.request.content = b"paramx=x"

        # same parameters
        assert s._hash(r) == s._hash(r2)


def test_ignore_payload_params_other_content_type():
    s = serverplayback.ServerPlayback()
    with taddons.context(s) as tctx:
        tctx.configure(
            s,
            server_replay_ignore_content=False,
            server_replay_ignore_payload_params=["param1", "param2"],
        )

        r = tflow.tflow(resp=True)
        r.request.headers["Content-Type"] = "application/json"
        r.request.content = b'{"param1":"1"}'
        r2 = tflow.tflow(resp=True)
        r2.request.headers["Content-Type"] = "application/json"
        r2.request.content = b'{"param1":"1"}'
        # same content
        assert s._hash(r) == s._hash(r2)
        # distinct content (note only x-www-form-urlencoded payload is analysed)
        r2.request.content = b'{"param1":"2"}'
        assert not s._hash(r) == s._hash(r2)


def test_hash():
    s = serverplayback.ServerPlayback()
    with taddons.context(s) as tctx:
        tctx.configure(s)

        r = tflow.tflow()
        r2 = tflow.tflow()

        assert s._hash(r)
        assert s._hash(r) == s._hash(r2)
        r.request.headers["foo"] = "bar"
        assert s._hash(r) == s._hash(r2)
        r.request.path = "voing"
        assert s._hash(r) != s._hash(r2)

        r.request.path = "path?blank_value"
        r2.request.path = "path?"
        assert s._hash(r) != s._hash(r2)


def test_headers():
    s = serverplayback.ServerPlayback()
    with taddons.context(s) as tctx:
        tctx.configure(s, server_replay_use_headers=["foo"])

        r = tflow.tflow(resp=True)
        r.request.headers["foo"] = "bar"
        r2 = tflow.tflow(resp=True)
        assert not s._hash(r) == s._hash(r2)
        r2.request.headers["foo"] = "bar"
        assert s._hash(r) == s._hash(r2)
        r2.request.headers["oink"] = "bar"
        assert s._hash(r) == s._hash(r2)

        r = tflow.tflow(resp=True)
        r2 = tflow.tflow(resp=True)
        assert s._hash(r) == s._hash(r2)


def test_load():
    s = serverplayback.ServerPlayback()
    with taddons.context(s) as tctx:
        tctx.configure(s)

        r = tflow.tflow(resp=True)
        r.request.headers["key"] = "one"

        r2 = tflow.tflow(resp=True)
        r2.request.headers["key"] = "two"

        s.load_flows([r, r2])

        assert s.count() == 2

        n = s.next_flow(r)
        assert n.request.headers["key"] == "one"
        assert s.count() == 1

        n = s.next_flow(r)
        assert n.request.headers["key"] == "two"
        assert not s.flowmap
        assert s.count() == 0

        assert not s.next_flow(r)


def test_load_with_server_replay_reuse():
    s = serverplayback.ServerPlayback()
    with taddons.context(s) as tctx:
        tctx.configure(s, server_replay_reuse=True)

        r = tflow.tflow(resp=True)
        r.request.headers["key"] = "one"

        r2 = tflow.tflow(resp=True)
        r2.request.headers["key"] = "two"

        s.load_flows([r, r2])

        assert s.count() == 2
        s.next_flow(r)
        assert s.count() == 2


def test_ignore_params():
    s = serverplayback.ServerPlayback()
    with taddons.context(s) as tctx:
        tctx.configure(s, server_replay_ignore_params=["param1", "param2"])

        r = tflow.tflow(resp=True)
        r.request.path = "/test?param1=1"
        r2 = tflow.tflow(resp=True)
        r2.request.path = "/test"
        assert s._hash(r) == s._hash(r2)
        r2.request.path = "/test?param1=2"
        assert s._hash(r) == s._hash(r2)
        r2.request.path = "/test?param2=1"
        assert s._hash(r) == s._hash(r2)
        r2.request.path = "/test?param3=2"
        assert not s._hash(r) == s._hash(r2)


def thash(r, r2, setter):
    s = serverplayback.ServerPlayback()
    with taddons.context(s) as tctx:
        s = serverplayback.ServerPlayback()
        tctx.configure(s, server_replay_ignore_payload_params=["param1", "param2"])

        setter(r, paramx="x", param1="1")

        setter(r2, paramx="x", param1="1")
        # same parameters
        assert s._hash(r) == s._hash(r2)
        # ignored parameters !=
        setter(r2, paramx="x", param1="2")
        assert s._hash(r) == s._hash(r2)
        # missing parameter
        setter(r2, paramx="x")
        assert s._hash(r) == s._hash(r2)
        # ignorable parameter added
        setter(r2, paramx="x", param1="2")
        assert s._hash(r) == s._hash(r2)
        # not ignorable parameter changed
        setter(r2, paramx="y", param1="1")
        assert not s._hash(r) == s._hash(r2)
        # not ignorable parameter missing
        setter(r2, param1="1")
        r2.request.content = b"param1=1"
        assert not s._hash(r) == s._hash(r2)


def test_ignore_payload_params():
    def urlencode_setter(r, **kwargs):
        r.request.content = urllib.parse.urlencode(kwargs).encode()

    r = tflow.tflow(resp=True)
    r.request.headers["Content-Type"] = "application/x-www-form-urlencoded"
    r2 = tflow.tflow(resp=True)
    r2.request.headers["Content-Type"] = "application/x-www-form-urlencoded"
    thash(r, r2, urlencode_setter)

    boundary = "somefancyboundary"

    def multipart_setter(r, **kwargs):
        b = f"--{boundary}\n"
        parts = []
        for k, v in kwargs.items():
            parts.append('Content-Disposition: form-data; name="%s"\n\n%s\n' % (k, v))
        c = b + b.join(parts) + b
        r.request.content = c.encode()
        r.request.headers["content-type"] = "multipart/form-data; boundary=" + boundary

    r = tflow.tflow(resp=True)
    r2 = tflow.tflow(resp=True)
    thash(r, r2, multipart_setter)


def test_runtime_modify_params():
    s = serverplayback.ServerPlayback()
    with taddons.context(s) as tctx:
        r = tflow.tflow(resp=True)
        r.request.path = "/test?param1=1"
        r2 = tflow.tflow(resp=True)
        r2.request.path = "/test"

        s.load_flows([r])
        hash = next(iter(s.flowmap.keys()))

        tctx.configure(s, server_replay_ignore_params=["param1"])
        hash_mod = next(iter(s.flowmap.keys()))

        assert hash != hash_mod
        assert hash_mod == s._hash(r2)


def test_server_playback_full():
    s = serverplayback.ServerPlayback()
    with taddons.context(s) as tctx:
        tctx.configure(
            s,
            server_replay_refresh=True,
        )

        f = tflow.tflow()
        f.response = mitmproxy.test.tutils.tresp(content=f.request.content)
        s.load_flows([f, f])

        tf = tflow.tflow()
        assert not tf.response
        s.request(tf)
        assert tf.response.data == f.response.data

        tf = tflow.tflow()
        tf.request.content = b"gibble"
        assert not tf.response
        s.request(tf)
        assert not tf.response


async def test_server_playback_kill():
    s = serverplayback.ServerPlayback()
    with taddons.context(s) as tctx:
        tctx.configure(s, server_replay_refresh=True, server_replay_kill_extra=True)

        f = tflow.tflow()
        f.response = mitmproxy.test.tutils.tresp(content=f.request.content)
        s.load_flows([f])

        f = tflow.tflow()
        f.request.host = "nonexistent"
        await tctx.cycle(s, f)
        assert f.error


async def test_server_playback_kill_new_option():
    s = serverplayback.ServerPlayback()
    with taddons.context(s) as tctx:
        tctx.configure(s, server_replay_refresh=True, server_replay_extra="kill")

        f = tflow.tflow()
        f.response = mitmproxy.test.tutils.tresp(content=f.request.content)
        s.load_flows([f])

        f = tflow.tflow()
        f.request.host = "nonexistent"
        await tctx.cycle(s, f)
        assert f.error


@pytest.mark.parametrize(
    "option,status",
    [
        ("204", 204),
        ("400", 400),
        ("404", 404),
        ("500", 500),
    ],
)
async def test_server_playback_404(option, status):
    s = serverplayback.ServerPlayback()
    with taddons.context(s) as tctx:
        tctx.configure(s, server_replay_refresh=True, server_replay_extra=option)

        f = tflow.tflow()
        f.response = mitmproxy.test.tutils.tresp(content=f.request.content)
        s.load_flows([f])

        f = tflow.tflow()
        f.request.host = "nonexistent"
        s.request(f)
        assert f.response.status_code == status


def test_server_playback_response_deleted():
    """
    The server playback addon holds references to flows that can be modified by the user in the meantime.
    One thing that can happen is that users remove the response object. This happens for example when doing a client
    replay at the same time.
    """
    sp = serverplayback.ServerPlayback()
    with taddons.context(sp) as tctx:
        tctx.configure(sp)
        f1 = tflow.tflow(resp=True)
        f2 = tflow.tflow(resp=True)

        assert not sp.flowmap

        sp.load_flows([f1, f2])
        assert sp.flowmap

        f1.response = f2.response = None
        assert not sp.next_flow(f1)
        assert not sp.flowmap


# --- match-key construction regressions (uf-t283) --------------------------
#
# The match key must (a) keep the exact same equivalence relation as before
# under every combination of the existing options, (b) stay unambiguous so
# that adjacent requests which would collide under naive concatenation do not
# match, and (c) not pay a large-body copy chain before hashing.


_HASH_OPTION_GRID = {
    "server_replay_ignore_content": [False, True],
    "server_replay_ignore_host": [False, True],
    "server_replay_ignore_port": [False, True],
    "server_replay_ignore_params": [[], ["a"]],
    "server_replay_ignore_payload_params": [[], ["param1"]],
    "server_replay_use_headers": [[], ["foo"]],
}


def _reference_hash(flow, options):
    """
    The pre-existing match-key construction, kept verbatim as the semantic
    oracle. Only the final serialization differs (that is the formula change
    under test); the equivalence relation must be identical.
    """
    r = flow.request
    _, _, path, _, query, _ = urllib.parse.urlparse(r.url)
    queriesArray = urllib.parse.parse_qsl(query, keep_blank_values=True)

    key = [str(r.scheme), str(r.method), str(path)]
    if not options["server_replay_ignore_content"]:
        if options["server_replay_ignore_payload_params"] and r.multipart_form:
            key.extend(
                (k, v)
                for k, v in r.multipart_form.items(multi=True)
                if k.decode(errors="replace")
                not in options["server_replay_ignore_payload_params"]
            )
        elif options["server_replay_ignore_payload_params"] and r.urlencoded_form:
            key.extend(
                (k, v)
                for k, v in r.urlencoded_form.items(multi=True)
                if k not in options["server_replay_ignore_payload_params"]
            )
        else:
            key.append(str(r.raw_content))

    if not options["server_replay_ignore_host"]:
        key.append(r.pretty_host)
    if not options["server_replay_ignore_port"]:
        key.append(r.port)

    filtered = []
    ignore_params = options["server_replay_ignore_params"] or []
    for p in queriesArray:
        if p[0] not in ignore_params:
            filtered.append(p)
    for p in filtered:
        key.append(p[0])
        key.append(p[1])

    if options["server_replay_use_headers"]:
        headers = []
        for i in options["server_replay_use_headers"]:
            v = r.headers.get(i)
            headers.append((i, v))
        key.append(headers)
    return repr(key)


def _semantic_flows():
    """A flow zoo that exercises every branch of the key construction."""
    flows = []
    for _ in range(10):
        flows.append(tflow.tflow(resp=True))

    flows[1].request.content = b"foo\x00\xff\xfe binary"
    flows[2].request.content = b""
    flows[3].request.raw_content = None
    flows[4].request.path = "/p?a=1&b=2&a=3"
    flows[5].request.path = "/p?a=1&b=2&a=4"
    flows[6].request.headers["foo"] = "bar"
    flows[7].request.headers["foo"] = "baz"
    flows[8].request.host = "other"
    flows[9].request.port = 1234

    # urlencoded payload, distinct ordering of the ignorable parameter
    f = tflow.tflow(resp=True)
    f.request.headers["Content-Type"] = "application/x-www-form-urlencoded"
    f.request.content = b"a=1&param1=3&b=2"
    flows.append(f)
    f = tflow.tflow(resp=True)
    f.request.headers["Content-Type"] = "application/x-www-form-urlencoded"
    f.request.content = b"a=1&b=2&param1=4"
    flows.append(f)

    # multipart payloads differing only in the ignorable part
    for value in (b"2", b"3"):
        f = tflow.tflow(resp=True)
        f.request.headers["content-type"] = "multipart/form-data; boundary=zz"
        f.request.content = (
            b'--zz\nContent-Disposition: form-data; name="a"\n\n1\n'
            b'--zz\nContent-Disposition: form-data; name="param1"\n\n'
            + value
            + b"\n--zz--\r\n"
        )
        flows.append(f)

    return flows


def test_hash_semantics_match_reference():
    """Option-combination match semantics are unchanged."""
    flows = _semantic_flows()
    names = list(_HASH_OPTION_GRID)
    for combo in itertools.product(*_HASH_OPTION_GRID.values()):
        options = dict(zip(names, combo))
        s = serverplayback.ServerPlayback()
        with taddons.context(s) as tctx:
            tctx.configure(s, **options)
            reference = [_reference_hash(f, options) for f in flows]
            actual = [s._hash(f) for f in flows]
        for i in range(len(flows)):
            for j in range(i, len(flows)):
                assert (reference[i] == reference[j]) == (
                    actual[i] == actual[j]
                ), f"option combination {options!r} diverges on flows {i} and {j}"


def test_hash_rejects_ambiguous_concatenation():
    """
    Two requests whose fields run together under naive concatenation must
    still hash differently. Replay traffic carries same and near-variant
    requests back to back, so a boundary slip would make a variant match a
    recorded flow it should miss.
    """
    s = serverplayback.ServerPlayback()
    with taddons.context(s) as tctx:
        tctx.configure(s)

        # "GET" + "/ab" vs. a method that swallows the path prefix.
        r1 = tflow.tflow(resp=True)
        r1.request.method = "GET"
        r1.request.path = "/ab"
        r2 = tflow.tflow(resp=True)
        r2.request.method = "GET/ab"
        r2.request.path = ""
        assert s._hash(r1) != s._hash(r2)

        # body that ends where the next field begins: "a"+"bc" vs. "ab"+"c"
        r3 = tflow.tflow(resp=True)
        r3.request.content = b"a"
        r3.request.host = "bc"
        r4 = tflow.tflow(resp=True)
        r4.request.content = b"ab"
        r4.request.host = "c"
        assert s._hash(r3) != s._hash(r4)

        # same characters, different split between query name and value
        r5 = tflow.tflow(resp=True)
        r5.request.path = "/p?ab=c"
        r6 = tflow.tflow(resp=True)
        r6.request.path = "/p?a=bc"
        assert s._hash(r5) != s._hash(r6)


def _time_match(s, flow, rounds=5):
    s._hash(flow)  # warm caches so we measure construction, not the first touch
    start = time.perf_counter()
    for _ in range(rounds):
        s._hash(flow)
    return (time.perf_counter() - start) / rounds


def test_hash_large_body_cost_and_memory():
    """
    A single match on an 8MB binary body must stay at digest scale and must
    not allocate a body-sized copy chain: <40ms per match and <2x body size
    peak, as stated in the delivery notes.
    """
    body = bytes(8 * 1024 * 1024)
    s = serverplayback.ServerPlayback()
    with taddons.context(s) as tctx:
        tctx.configure(s)
        f = tflow.tflow(resp=True)
        f.request.content = body

        elapsed = _time_match(s, f)
        assert elapsed < 0.040, f"8MB match took {elapsed * 1000:.2f}ms (>=40ms)"

        tracemalloc.start()
        try:
            tracemalloc.reset_peak()
            s._hash(f)
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        assert peak < 2 * len(body), (
            f"8MB match peaked at {peak / 1e6:.2f}MB "
            f"({peak / len(body):.2f}x body), expected <2x"
        )


def test_load_200_one_mb_sessions_speed():
    """Batch-loading 200 x 1MB sessions must stay well under a few seconds."""
    s = serverplayback.ServerPlayback()
    with taddons.context(s) as tctx:
        tctx.configure(s)
        flows = []
        for i in range(200):
            f = tflow.tflow(resp=True)
            f.request.content = bytes([i % 256]) * (1024 * 1024)
            flows.append(f)

        start = time.perf_counter()
        s.load_flows(flows)
        elapsed = time.perf_counter() - start
        assert elapsed < 2.0, f"loading 200 x 1MB took {elapsed:.2f}s (>=2s)"
        assert s.count() == 200
