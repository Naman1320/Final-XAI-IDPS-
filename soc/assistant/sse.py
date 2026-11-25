"""Read JSON events from a server-sent event stream."""

import json
from collections.abc import Iterable, Iterator


def events(lines: Iterable[bytes]) -> Iterator[dict]:
    data = []
    for line in lines:
        line = line.decode().rstrip("\r\n")
        if line == "data: [DONE]":
            return
        if line.startswith("data:"):
            data.append(line[5:].lstrip())
        elif not line and data:
            yield json.loads("\n".join(data))
            data.clear()
    if data:
        yield json.loads("\n".join(data))
