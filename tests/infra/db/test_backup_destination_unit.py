"""Unit tests for `infra.db.backup.destination` -- the off-site
`BackupDestination` abstraction. `FakeBackupDestination`/
`LocalBackupDestination` are exercised for real (no mocking needed --
they are real, small implementations); `S3CompatibleBackupDestination`
is exercised against a mocked `boto3` client only (never a live cloud
provider from a unit test -- module docstring's own "no ordinary unit
test may depend on an external cloud provider").
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest
from infra.db.backup.destination import (
    BackupDestinationError,
    FakeBackupDestination,
    LocalBackupDestination,
    S3CompatibleBackupDestination,
    S3DestinationConfig,
    apply_retention,
    get_s3_destination_config,
)

# --- FakeBackupDestination ----------------------------------------------


def test_fake_destination_round_trips_upload_and_download(tmp_path: Path) -> None:
    destination = FakeBackupDestination()
    source = tmp_path / "artifact.pgdump.age"
    source.write_bytes(b"encrypted payload")

    destination.upload(source, "postgres/artifact.pgdump.age")
    downloaded = tmp_path / "downloaded.pgdump.age"
    destination.download("postgres/artifact.pgdump.age", downloaded)
    assert downloaded.read_bytes() == b"encrypted payload"


def test_fake_destination_upload_rejects_missing_local_file(tmp_path: Path) -> None:
    destination = FakeBackupDestination()
    with pytest.raises(BackupDestinationError):
        destination.upload(tmp_path / "missing.pgdump", "postgres/missing.pgdump")


def test_fake_destination_download_rejects_missing_key(tmp_path: Path) -> None:
    destination = FakeBackupDestination()
    with pytest.raises(BackupDestinationError):
        destination.download("postgres/missing.pgdump", tmp_path / "out.pgdump")


def test_fake_destination_list_objects_filters_by_prefix(tmp_path: Path) -> None:
    destination = FakeBackupDestination()
    a = tmp_path / "a.pgdump"
    a.write_bytes(b"a")
    destination.upload(a, "postgres/a.pgdump")
    destination.upload(a, "other/a.pgdump")

    listed = destination.list_objects("postgres/")
    assert [o.key for o in listed] == ["postgres/a.pgdump"]


def test_fake_destination_delete_is_idempotent(tmp_path: Path) -> None:
    destination = FakeBackupDestination()
    destination.delete_object("postgres/never-existed.pgdump")  # must not raise


# --- LocalBackupDestination ----------------------------------------------


def test_local_destination_requires_absolute_root(tmp_path: Path) -> None:
    with pytest.raises(BackupDestinationError):
        LocalBackupDestination(Path("relative/path"))


def test_local_destination_round_trips_upload_and_download(tmp_path: Path) -> None:
    root = tmp_path / "off-site-root"
    destination = LocalBackupDestination(root)
    source = tmp_path / "artifact.pgdump.age"
    source.write_bytes(b"encrypted payload")

    destination.upload(source, "postgres/artifact.pgdump.age")
    assert (root / "postgres" / "artifact.pgdump.age").is_file()

    downloaded = tmp_path / "downloaded.pgdump.age"
    destination.download("postgres/artifact.pgdump.age", downloaded)
    assert downloaded.read_bytes() == b"encrypted payload"


@pytest.mark.parametrize(
    "key",
    ["../escape.pgdump", "/etc/passwd", "postgres/../../escape.pgdump"],
)
def test_local_destination_rejects_path_traversal_keys(tmp_path: Path, key: str) -> None:
    destination = LocalBackupDestination(tmp_path / "root")
    with pytest.raises(BackupDestinationError):
        destination._path_for(key)


def test_local_destination_list_objects_filters_by_prefix(tmp_path: Path) -> None:
    root = tmp_path / "root"
    destination = LocalBackupDestination(root)
    source = tmp_path / "a.pgdump"
    source.write_bytes(b"a")
    destination.upload(source, "postgres/a.pgdump")
    destination.upload(source, "other/a.pgdump")

    listed = destination.list_objects("postgres/")
    assert [o.key for o in listed] == ["postgres/a.pgdump"]


def test_local_destination_delete_is_idempotent(tmp_path: Path) -> None:
    destination = LocalBackupDestination(tmp_path / "root")
    destination.delete_object("postgres/never-existed.pgdump")  # must not raise


# --- get_s3_destination_config --------------------------------------------


class _FakeSecrets:
    def __init__(self, values: dict[str, str]) -> None:
        self._values = values

    def get(self, name: str) -> str | None:
        return self._values.get(name)


def test_get_s3_destination_config_reads_through_secrets_provider(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "infra.db.backup.destination.get_secrets_provider",
        lambda: _FakeSecrets(
            {
                "BACKUP_S3_ENDPOINT_URL": "https://s3.example.com",
                "BACKUP_S3_BUCKET": "backups-bucket",
                "BACKUP_S3_ACCESS_KEY_ID": "AKIAFAKE",
                "BACKUP_S3_SECRET_ACCESS_KEY": "fake-secret",
                "BACKUP_S3_REGION": "eu-west-1",
            }
        ),
    )
    config = get_s3_destination_config()
    assert config.endpoint_url == "https://s3.example.com"
    assert config.bucket == "backups-bucket"
    assert config.region == "eu-west-1"


def test_get_s3_destination_config_lists_every_missing_value(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "infra.db.backup.destination.get_secrets_provider",
        lambda: _FakeSecrets({"BACKUP_S3_BUCKET": "backups-bucket"}),
    )
    with pytest.raises(BackupDestinationError) as excinfo:
        get_s3_destination_config()
    message = str(excinfo.value)
    assert "BACKUP_S3_ENDPOINT_URL" in message
    assert "BACKUP_S3_ACCESS_KEY_ID" in message
    assert "BACKUP_S3_SECRET_ACCESS_KEY" in message
    assert "fake-secret" not in message


# --- S3CompatibleBackupDestination (mocked boto3 client) -------------------


@pytest.fixture()
def s3_config() -> S3DestinationConfig:
    return S3DestinationConfig(
        endpoint_url="https://s3.example.com",
        bucket="backups-bucket",
        access_key_id="AKIAFAKE",
        secret_access_key="fake-secret",
        region="us-east-1",
    )


def _build_destination_with_mock_client(
    monkeypatch: pytest.MonkeyPatch, s3_config: S3DestinationConfig
) -> tuple[S3CompatibleBackupDestination, MagicMock]:
    mock_client = MagicMock()
    mock_boto3 = MagicMock()
    mock_boto3.client.return_value = mock_client
    monkeypatch.setitem(__import__("sys").modules, "boto3", mock_boto3)
    destination = S3CompatibleBackupDestination(s3_config)
    return destination, mock_client


def test_s3_destination_upload_calls_boto3_upload_file(
    monkeypatch: pytest.MonkeyPatch, s3_config: S3DestinationConfig, tmp_path: Path
) -> None:
    destination, mock_client = _build_destination_with_mock_client(monkeypatch, s3_config)
    source = tmp_path / "artifact.pgdump.age"
    source.write_bytes(b"data")

    destination.upload(source, "postgres/artifact.pgdump.age")
    mock_client.upload_file.assert_called_once_with(
        str(source), "backups-bucket", "postgres/artifact.pgdump.age"
    )


def test_s3_destination_upload_normalizes_boto3_exceptions(
    monkeypatch: pytest.MonkeyPatch, s3_config: S3DestinationConfig, tmp_path: Path
) -> None:
    destination, mock_client = _build_destination_with_mock_client(monkeypatch, s3_config)
    mock_client.upload_file.side_effect = RuntimeError("some botocore-internal detail")
    source = tmp_path / "artifact.pgdump.age"
    source.write_bytes(b"data")

    with pytest.raises(BackupDestinationError) as excinfo:
        destination.upload(source, "postgres/artifact.pgdump.age")
    assert "some botocore-internal detail" not in str(excinfo.value)
    assert excinfo.value.operation == "upload"


def test_s3_destination_download_calls_boto3_download_file(
    monkeypatch: pytest.MonkeyPatch, s3_config: S3DestinationConfig, tmp_path: Path
) -> None:
    destination, mock_client = _build_destination_with_mock_client(monkeypatch, s3_config)
    target = tmp_path / "downloaded.pgdump.age"

    destination.download("postgres/artifact.pgdump.age", target)
    mock_client.download_file.assert_called_once_with(
        "backups-bucket", "postgres/artifact.pgdump.age", str(target)
    )


def test_s3_destination_list_objects_paginates(
    monkeypatch: pytest.MonkeyPatch, s3_config: S3DestinationConfig
) -> None:
    destination, mock_client = _build_destination_with_mock_client(monkeypatch, s3_config)
    mock_paginator = MagicMock()
    mock_client.get_paginator.return_value = mock_paginator

    import datetime as dt

    mock_paginator.paginate.return_value = [
        {
            "Contents": [
                {
                    "Key": "postgres/a.pgdump.age",
                    "Size": 10,
                    "LastModified": dt.datetime(2026, 1, 1),
                }
            ]
        }
    ]

    listed = destination.list_objects("postgres/")
    assert len(listed) == 1
    assert listed[0].key == "postgres/a.pgdump.age"
    assert listed[0].size_bytes == 10


def test_s3_destination_delete_calls_boto3_delete_object(
    monkeypatch: pytest.MonkeyPatch, s3_config: S3DestinationConfig
) -> None:
    destination, mock_client = _build_destination_with_mock_client(monkeypatch, s3_config)
    destination.delete_object("postgres/artifact.pgdump.age")
    mock_client.delete_object.assert_called_once_with(
        Bucket="backups-bucket", Key="postgres/artifact.pgdump.age"
    )


# --- apply_retention -------------------------------------------------------


def _seed(destination: FakeBackupDestination, keys_and_times: list[tuple[str, str]]) -> None:
    for key, last_modified in keys_and_times:
        destination._objects[key] = b"x"
        destination._last_modified[key] = last_modified


def test_apply_retention_keeps_only_the_newest_n() -> None:
    destination = FakeBackupDestination()
    _seed(
        destination,
        [
            ("postgres/a", "2026-01-01T00:00:00+00:00"),
            ("postgres/b", "2026-01-02T00:00:00+00:00"),
            ("postgres/c", "2026-01-03T00:00:00+00:00"),
        ],
    )
    deleted = apply_retention(destination, prefix="postgres/", keep_last=2)
    assert deleted == ["postgres/a"]
    remaining = {o.key for o in destination.list_objects("postgres/")}
    assert remaining == {"postgres/b", "postgres/c"}


def test_apply_retention_never_deletes_the_single_newest_object_even_with_keep_last_zero() -> None:
    destination = FakeBackupDestination()
    _seed(
        destination,
        [
            ("postgres/a", "2026-01-01T00:00:00+00:00"),
            ("postgres/b", "2026-01-02T00:00:00+00:00"),
        ],
    )
    deleted = apply_retention(destination, prefix="postgres/", keep_last=0)
    assert deleted == ["postgres/a"]
    remaining = {o.key for o in destination.list_objects("postgres/")}
    assert remaining == {"postgres/b"}


def test_apply_retention_on_empty_destination_deletes_nothing() -> None:
    destination = FakeBackupDestination()
    assert apply_retention(destination, prefix="postgres/", keep_last=7) == []


def test_apply_retention_with_fewer_objects_than_keep_last_deletes_nothing() -> None:
    destination = FakeBackupDestination()
    _seed(destination, [("postgres/a", "2026-01-01T00:00:00+00:00")])
    assert apply_retention(destination, prefix="postgres/", keep_last=7) == []


def test_apply_retention_logs_deletion_without_secret_or_payload_content(
    caplog: pytest.LogCaptureFixture,
) -> None:
    destination = FakeBackupDestination()
    _seed(
        destination,
        [
            ("postgres/a", "2026-01-01T00:00:00+00:00"),
            ("postgres/b", "2026-01-02T00:00:00+00:00"),
        ],
    )
    with caplog.at_level("INFO"):
        apply_retention(destination, prefix="postgres/", keep_last=1)
    records = [r for r in caplog.records if r.message == "backup_retention_deleted"]
    assert len(records) == 1
    assert records[0].__dict__["object_key"] == "postgres/a"
    assert records[0].__dict__["object_size_bytes"] == 1
