from uuid import uuid4

from app.api.v1 import hosts


def test_inventory_is_kept_per_organization_and_expires() -> None:
    hosts._hosts_cache.clear()
    first, second = uuid4(), uuid4()
    hosts._store_hosts(first, [{"host_id": "a"}], now=100.0)
    assert hosts._cached_hosts(first, now=105.0) == [{"host_id": "a"}]
    assert hosts._cached_hosts(second, now=105.0) is None
    assert hosts._cached_hosts(first, now=100.0 + hosts.HOSTS_CACHE_SECONDS + 0.1) is None


def test_cache_is_bounded() -> None:
    hosts._hosts_cache.clear()
    for _ in range(300):
        hosts._store_hosts(uuid4(), [], now=1.0)
    assert len(hosts._hosts_cache) <= 257
