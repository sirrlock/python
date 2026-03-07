from __future__ import annotations

import pytest

from sirr import SecretMeta


def test_from_dict_full():
    meta = SecretMeta.from_dict(
        {
            "key": "MY_KEY",
            "created_at": 1700000000,
            "read_count": 2,
            "expires_at": 1700003600,
            "max_reads": 5,
        }
    )
    assert meta.key == "MY_KEY"
    assert meta.created_at == 1700000000
    assert meta.read_count == 2
    assert meta.expires_at == 1700003600
    assert meta.max_reads == 5


def test_from_dict_optional_fields():
    meta = SecretMeta.from_dict(
        {
            "key": "K",
            "created_at": 100,
            "read_count": 0,
        }
    )
    assert meta.expires_at is None
    assert meta.max_reads is None


def test_frozen():
    meta = SecretMeta(key="K", created_at=1, read_count=0)
    with pytest.raises(AttributeError):
        meta.key = "other"  # type: ignore[misc]
