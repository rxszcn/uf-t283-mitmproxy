import hashlib
import logging
import urllib
from collections.abc import Hashable
from collections.abc import Sequence

import mitmproxy.types
from mitmproxy import command
from mitmproxy import ctx
from mitmproxy import exceptions
from mitmproxy import flow
from mitmproxy import hooks
from mitmproxy import http
from mitmproxy import io

logger = logging.getLogger(__name__)

HASH_OPTIONS = [
    "server_replay_ignore_content",
    "server_replay_ignore_host",
    "server_replay_ignore_params",
    "server_replay_ignore_payload_params",
    "server_replay_ignore_port",
    "server_replay_use_headers",
]


class ServerPlayback:
    flowmap: dict[Hashable, list[http.HTTPFlow]]
    configured: bool

    def __init__(self):
        self.flowmap = {}
        self.configured = False

    def load(self, loader):
        loader.add_option(
            "server_replay_kill_extra",
            bool,
            False,
            "Kill extra requests during replay (for which no replayable response was found)."
            "[Deprecated, prefer to use server_replay_extra='kill']",
        )
        loader.add_option(
            "server_replay_extra",
            str,
            "forward",
            "Behaviour for extra requests during replay for which no replayable response was found. "
            "Setting a numeric string value will return an empty HTTP response with the respective status code.",
            choices=["forward", "kill", "204", "400", "404", "500"],
        )
        loader.add_option(
            "server_replay_reuse",
            bool,
            False,
            """
            Don't remove flows from server replay state after use. This makes it
            possible to replay same response multiple times.
            """,
        )
        loader.add_option(
            "server_replay_nopop",
            bool,
            False,
            """
            Deprecated alias for `server_replay_reuse`.
            """,
        )
        loader.add_option(
            "server_replay_refresh",
            bool,
            True,
            """
            Refresh server replay responses by adjusting date, expires and
            last-modified headers, as well as adjusting cookie expiration.
            """,
        )
        loader.add_option(
            "server_replay_use_headers",
            Sequence[str],
            [],
            """
            Request headers that need to match while searching for a saved flow
            to replay.
            """,
        )
        loader.add_option(
            "server_replay",
            Sequence[str],
            [],
            "Replay server responses from a saved file.",
        )
        loader.add_option(
            "server_replay_ignore_content",
            bool,
            False,
            "Ignore request content while searching for a saved flow to replay.",
        )
        loader.add_option(
            "server_replay_ignore_params",
            Sequence[str],
            [],
            """
            Request parameters to be ignored while searching for a saved flow
            to replay.
            """,
        )
        loader.add_option(
            "server_replay_ignore_payload_params",
            Sequence[str],
            [],
            """
            Request payload parameters (application/x-www-form-urlencoded or
            multipart/form-data) to be ignored while searching for a saved flow
            to replay.
            """,
        )
        loader.add_option(
            "server_replay_ignore_host",
            bool,
            False,
            """
            Ignore request destination host while searching for a saved flow
            to replay.
            """,
        )
        loader.add_option(
            "server_replay_ignore_port",
            bool,
            False,
            """
            Ignore request destination port while searching for a saved flow
            to replay.
            """,
        )

    @command.command("replay.server")
    def load_flows(self, flows: Sequence[flow.Flow]) -> None:
        """
        Replay server responses from flows.
        """
        self.flowmap = {}
        self.add_flows(flows)

    @command.command("replay.server.add")
    def add_flows(self, flows: Sequence[flow.Flow]) -> None:
        """
        Add responses from flows to server replay list.
        """
        for f in flows:
            if isinstance(f, http.HTTPFlow):
                lst = self.flowmap.setdefault(self._hash(f), [])
                lst.append(f)
        ctx.master.addons.trigger(hooks.UpdateHook([]))

    @command.command("replay.server.file")
    def load_file(self, path: mitmproxy.types.Path) -> None:
        try:
            flows = io.read_flows_from_paths([path])
        except exceptions.FlowReadException as e:
            raise exceptions.CommandError(str(e))
        self.load_flows(flows)

    @command.command("replay.server.stop")
    def clear(self) -> None:
        """
        Stop server replay.
        """
        self.flowmap = {}
        ctx.master.addons.trigger(hooks.UpdateHook([]))

    @command.command("replay.server.count")
    def count(self) -> int:
        return sum(len(i) for i in self.flowmap.values())

    def _hash(self, flow: http.HTTPFlow) -> Hashable:
        """
        Calculates a loose hash of the flow request.

        The key is a self-delimiting stream of type-tagged, length-prefixed
        components fed to SHA-256 incrementally. Each component carries a tag
        (``s`` str, ``i`` int, ``b`` bytes, ``n`` None, ``H`` header list) and
        its length, so distinct component sequences can never serialize to the
        same byte stream - "adjacent" requests that would collide under naive
        concatenation stay distinct. The request body is hashed straight from
        ``raw_content`` rather than going through ``str()`` (which expands
        non-printable binary data up to 4x) and another ``repr()`` copy. The
        equivalence relation is unchanged: same requests match, different ones
        don't.
        """
        r = flow.request
        _, _, path, _, query, _ = urllib.parse.urlparse(r.url)
        queriesArray = urllib.parse.parse_qsl(query, keep_blank_values=True)

        h = hashlib.sha256()
        h.update(b"mitmproxy/serverplayback/v2\x00")

        def feed(tag: bytes, payload: bytes) -> None:
            h.update(tag)
            h.update(len(payload).to_bytes(8, "big"))
            h.update(payload)

        def feed_item(tag: bytes, item) -> None:
            if item is None:
                h.update(b"n")
                h.update((0).to_bytes(8, "big"))
                return
            if isinstance(item, str):
                item = item.encode("utf8", "surrogateescape")
            h.update(tag)
            h.update(len(item).to_bytes(8, "big"))
            h.update(item)

        def feed_str(value: str) -> None:
            feed_item(b"s", value)

        def feed_pairs(tag: bytes, pairs, as_bytes: bool) -> None:
            # Each element is individually tagged and length-prefixed, so the
            # pair list is self-delimiting even when values are huge (e.g. a
            # multipart file part); nothing large is copied in the process.
            item_tag = b"b" if as_bytes else b"s"
            h.update(tag)
            h.update(len(pairs).to_bytes(8, "big"))
            for k, v in pairs:
                feed_item(item_tag, k)
                feed_item(item_tag, v)

        feed_str(str(r.scheme))
        feed_str(str(r.method))
        feed_str(str(path))

        if not ctx.options.server_replay_ignore_content:
            ignore_payload_params = ctx.options.server_replay_ignore_payload_params
            multipart = r.multipart_form.fields if ignore_payload_params else ()
            urlencoded = r.urlencoded_form.fields if ignore_payload_params else ()
            if multipart:
                feed_pairs(
                    b"M",
                    [
                        (k, v)
                        for k, v in multipart
                        if k.decode(errors="replace") not in ignore_payload_params
                    ],
                    as_bytes=True,
                )
            elif urlencoded:
                feed_pairs(
                    b"U",
                    [(k, v) for k, v in urlencoded if k not in ignore_payload_params],
                    as_bytes=False,
                )
            elif r.raw_content is None:
                feed(b"n", b"")
            else:
                feed(b"b", r.raw_content)

        if not ctx.options.server_replay_ignore_host:
            feed_str(r.pretty_host)
        if not ctx.options.server_replay_ignore_port:
            feed(b"i", str(r.port).encode())

        ignore_params = ctx.options.server_replay_ignore_params or []
        for name, value in queriesArray:
            if name not in ignore_params:
                feed_str(name)
                feed_str(value)

        use_headers = ctx.options.server_replay_use_headers
        if use_headers:
            feed_pairs(
                b"H",
                [(i, r.headers.get(i)) for i in use_headers],
                as_bytes=False,
            )

        return h.digest()

    def next_flow(self, flow: http.HTTPFlow) -> http.HTTPFlow | None:
        """
        Returns the next flow object, or None if no matching flow was
        found.
        """
        hash = self._hash(flow)
        if hash in self.flowmap:
            if ctx.options.server_replay_reuse or ctx.options.server_replay_nopop:
                return next(
                    (flow for flow in self.flowmap[hash] if flow.response), None
                )
            else:
                ret = self.flowmap[hash].pop(0)
                while not ret.response:
                    if self.flowmap[hash]:
                        ret = self.flowmap[hash].pop(0)
                    else:
                        del self.flowmap[hash]
                        return None
                if not self.flowmap[hash]:
                    del self.flowmap[hash]
                return ret
        else:
            return None

    def configure(self, updated):
        if ctx.options.server_replay_kill_extra:
            logger.warning(
                "server_replay_kill_extra has been deprecated, "
                "please update your config to use server_replay_extra='kill'."
            )
        if ctx.options.server_replay_nopop:  # pragma: no cover
            logger.error(
                "server_replay_nopop has been renamed to server_replay_reuse, please update your config."
            )
        if not self.configured and ctx.options.server_replay:
            self.configured = True
            try:
                flows = io.read_flows_from_paths(ctx.options.server_replay)
            except exceptions.FlowReadException as e:
                raise exceptions.OptionsError(str(e))
            self.load_flows(flows)
        if any(option in updated for option in HASH_OPTIONS):
            self.recompute_hashes()

    def recompute_hashes(self) -> None:
        """
        Rebuild flowmap if the hashing method has changed during execution,
        see https://github.com/mitmproxy/mitmproxy/issues/4506
        """
        flows = [flow for lst in self.flowmap.values() for flow in lst]
        self.load_flows(flows)

    def request(self, f: http.HTTPFlow) -> None:
        if self.flowmap:
            rflow = self.next_flow(f)
            if rflow:
                assert rflow.response
                response = rflow.response.copy()
                if ctx.options.server_replay_refresh:
                    response.refresh()
                f.response = response
                f.is_replay = "response"
            elif (
                ctx.options.server_replay_kill_extra
                or ctx.options.server_replay_extra == "kill"
            ):
                logging.warning(
                    "server_playback: killed non-replay request {}".format(
                        f.request.url
                    )
                )
                f.kill()
            elif ctx.options.server_replay_extra != "forward":
                logging.warning(
                    "server_playback: returned {} non-replay request {}".format(
                        ctx.options.server_replay_extra, f.request.url
                    )
                )
                f.response = http.Response.make(int(ctx.options.server_replay_extra))
                f.is_replay = "response"
