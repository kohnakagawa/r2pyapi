import glob
import os
from pathlib import Path
from typing import List

import pytest
import r2pipe

from r2pyapi import R2Reader

test_bins: List[str] = glob.glob(
    os.path.join(os.path.abspath(os.path.splitext(__file__)[0]), "*.bin")
)


@pytest.mark.parametrize("test_bin", test_bins)
def test_read_bytes_at(test_bin: str, datadir: Path) -> None:
    r2 = r2pipe.open(str(datadir / test_bin))
    begin = 0x32
    size = 0x500
    with R2Reader(r2) as reader:
        bytes_read = reader.read_bytes_at(begin, size)
    assert bytes_read == list(i & 0xFF for i in range(begin, begin + size))


@pytest.mark.parametrize("test_bin", test_bins)
def test_read_bytes_hex_str_at(test_bin: str, datadir: Path) -> None:
    r2 = r2pipe.open(str(datadir / test_bin))
    begin = 0x30
    size = 0x500
    with R2Reader(r2) as reader:
        bytes_read = reader.read_bytes_as_hex_str_at(begin, size)
    assert bytes_read == "".join(f"{i & 0xff:02x}" for i in range(begin, begin + size))


@pytest.mark.parametrize("test_bin", test_bins)
def test_seek_is_restored(test_bin: str, datadir: Path) -> None:
    r2 = r2pipe.open(str(datadir / test_bin))

    pos_before = int(r2.cmd("s").strip(), 16)

    begin = 0x30
    size = 0x500
    with R2Reader(r2) as reader:
        _ = reader.read_bytes_as_hex_str_at(begin, size)

    pos_after = int(r2.cmd("s").strip(), 16)
    assert pos_after == pos_before
