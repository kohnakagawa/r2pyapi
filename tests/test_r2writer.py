import glob
import os
import shutil
from pathlib import Path
from typing import List

import pytest
import r2pipe

from r2pyapi import R2Writer

test_bins: List[str] = glob.glob(
    os.path.join(os.path.abspath(os.path.splitext(__file__)[0]), "*.bin")
)


@pytest.mark.parametrize("test_bin", test_bins)
def test_overwrite_bytes(test_bin: str, datadir: Path) -> None:
    src_file = str(datadir / test_bin)
    backup_file = str(datadir / test_bin) + ".back"
    shutil.copy(src=src_file, dst=backup_file)
    r2 = r2pipe.open(backup_file, flags=["-w"])

    size_before = r2.cmdj("ij")["core"]["size"]

    begin = 0x32
    size = 0x5000
    data = list(i & 0xFF for i in range(size))
    with R2Writer(r2) as writer:
        writer.overwrite_bytes(payload=data, address_at=begin)

    r2.cmdj(f"s {hex(begin)}")
    assert r2.cmdj(f"pxj {hex(size)}") == data

    size_after = r2.cmdj("ij")["core"]["size"]
    assert size_before == size_after


@pytest.mark.parametrize("test_bin", test_bins)
def test_insert_bytes(test_bin: str, datadir: Path) -> None:
    src_file = str(datadir / test_bin)
    backup_file = str(datadir / test_bin) + ".back"
    shutil.copy(src=src_file, dst=backup_file)
    r2 = r2pipe.open(backup_file)

    size_before = r2.cmdj("ij")["core"]["size"]

    begin = 0x32
    size = 0x5000
    data = list(i & 0xFF for i in range(size))
    with R2Writer(r2) as writer:
        writer.insert_bytes(payload=data, address_at=begin)

    r2.cmdj(f"s {hex(begin)}")
    assert r2.cmdj(f"pxj {hex(size)}") == data

    size_after = r2.cmdj("ij")["core"]["size"]
    assert size_before == size_after - size


@pytest.mark.parametrize("test_bin", test_bins)
def test_seek_is_restored(test_bin: str, datadir: Path) -> None:
    src_file = str(datadir / test_bin)
    backup_file = str(datadir / test_bin) + ".back"
    shutil.copy(src=src_file, dst=backup_file)
    r2 = r2pipe.open(backup_file, flags=["-w"])

    pos_before = int(r2.cmd("s").strip(), 16)

    begin = 0x32
    size = 0x5000
    data = list(i & 0xFF for i in range(size))
    with R2Writer(r2) as writer:
        writer.insert_bytes(payload=data, address_at=begin)

    pos_after = int(r2.cmd("s").strip(), 16)
    assert pos_before == pos_after
