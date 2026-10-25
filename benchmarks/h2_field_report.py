"""Exact accounting shared by correctness and timing runners (stdlib only)."""

HEADERS = b'\x88\x0f\x10\ntext/plain\x0f\r\x0213'


def validate_report(report, size, chunk, count, connections, pipeline):
    """Reconcile every worker and every byte, including setup, credit and fences."""
    assert report["requests"] == count * connections and report["errors"] == 0
    assert report["block_bytes"] == size and report["chunk"] == chunk
    assert report["connections"] == connections and report["pipeline"] == pipeline
    assert len(report["latencies_ns"]) == count * connections
    assert all(isinstance(n, int) and n > 0 for n in report["latencies_ns"])
    assert report["elapsed_seconds"] > 0 and report["rps"] > 0
    credit, updates, returned = 0, 0, 0
    for first in range(0, count, pipeline):
        credit += min(pipeline, count - first) * 13
        if credit >= 32768:
            updates += 1
            returned += credit
            credit = 0
    wire_size = size + 9 * ((size + 16383) // 16384)
    tx = 65 + count * wire_size + updates * 13
    # One HPACK size-update byte per connection, in the first response only.
    rx = 48 + count * (18 + len(HEADERS) + 13)
    writes = 4 + count * ((wire_size + chunk - 1) // chunk) + updates
    assert len(report["peers"]) == connections
    for i, peer in enumerate(report["peers"]):
        assert peer == dict(id=i, requests=count, samples=count, last_stream=2 * count - 1,
            field_bytes=count * size, sent_bytes=tx, received_bytes=rx,
            application_writes=writes, credit_updates=updates, returned_credit=returned), peer
    assert report["sent_bytes"] == tx * connections
    assert report["received_bytes"] == rx * connections
    assert report["application_writes"] == writes * connections
