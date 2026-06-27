from honeypot.storage import Event, EventStore


def test_record_assigns_id_and_timestamp(store):
    e = Event("", "203.0.113.1", 1234, 22, "ssh", 5, "hello", "sess1")
    rid = store.record(e)
    assert rid == 1
    assert e.id == 1
    assert e.timestamp  # auto-filled when empty


def test_counts(seeded_store):
    assert seeded_store.total_events() == 4
    assert seeded_store.unique_attackers() == 3


def test_recent_is_newest_first_and_limited(seeded_store):
    recent = seeded_store.recent(limit=2)
    assert len(recent) == 2
    assert recent[0].id > recent[1].id


def test_recent_limit_is_clamped(store):
    for i in range(5):
        store.record(Event("", f"10.0.0.{i}", 1, 22, "ssh", 0, "", f"s{i}"))
    assert len(store.recent(limit=0)) == 1  # clamped up to minimum 1
    assert len(store.recent(limit=9999)) == 5  # clamped down to available rows


def test_top_attackers_ranked_by_hits(seeded_store):
    top = seeded_store.top_attackers()
    assert top[0]["src_ip"] == "203.0.113.5"
    assert top[0]["hits"] == 2


def test_hits_by_port(seeded_store):
    by_port = {row["dst_port"]: row["hits"] for row in seeded_store.hits_by_port()}
    assert by_port[22] == 2
    assert by_port[23] == 1
    assert by_port[80] == 1


def test_hits_by_country(seeded_store):
    by_country = {r["country"]: r["hits"] for r in seeded_store.hits_by_country()}
    assert by_country["Narnia"] == 2


def test_timeline_buckets_by_hour(seeded_store):
    tl = seeded_store.timeline("hour")
    buckets = {row["bucket"]: row["hits"] for row in tl}
    assert buckets["2026-06-27T10"] == 2
    assert buckets["2026-06-27T11"] == 2


def test_stats_aggregates_everything(seeded_store):
    stats = seeded_store.stats()
    assert stats["total_events"] == 4
    assert stats["unique_attackers"] == 3
    assert len(stats["top_attackers"]) == 3
