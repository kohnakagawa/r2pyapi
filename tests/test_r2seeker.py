import glob
import os
from pathlib import Path
from typing import List

import pytest
import r2pipe

from r2pyapi import R2ByteSearchResult, R2Instruction, R2Seeker, R2SearchRegion

test_bins: List[str] = glob.glob(
    os.path.join(os.path.abspath(os.path.splitext(__file__)[0]), "*.bin")
)


@pytest.mark.parametrize("test_bin", test_bins)
def test_set_search_region(test_bin: str, datadir: Path) -> None:
    src_file = str(datadir / test_bin)
    r2 = r2pipe.open(src_file)

    region = R2SearchRegion(0x100, 0x200)
    R2Seeker.set_search_region(r2, region)

    region_after = R2SearchRegion(
        int(r2.cmd("e search.from").strip(), 16), int(r2.cmd("e search.to").strip(), 16)
    )

    assert region == region_after


@pytest.mark.parametrize("test_bin", test_bins)
def test_get_search_region(test_bin: str, datadir: Path) -> None:
    src_file = str(datadir / test_bin)
    r2 = r2pipe.open(src_file)

    region = R2SearchRegion(0x100, 0x200)

    r2.cmd(f"e search.from = {hex(region.start_addr)}")
    r2.cmd(f"e search.to = {hex(region.end_addr)}")

    assert region == R2Seeker.get_search_region(r2)


@pytest.mark.parametrize("test_bin", test_bins)
def test_get_pos(test_bin: str, datadir: Path) -> None:
    src_file = str(datadir / test_bin)
    r2 = r2pipe.open(src_file)
    pos = 0x100
    r2.cmd(f"s {pos}")
    assert R2Seeker.get_pos(r2) == pos


@pytest.mark.parametrize("test_bin", test_bins)
def test_seek_byte_sequences(test_bin: str, datadir: Path) -> None:
    src_file = str(datadir / test_bin)
    r2 = r2pipe.open(src_file)

    with R2Seeker(r2) as seeker:
        results = seeker.seek_byte_sequences([0x0, 0x1])

    refs = [
        R2ByteSearchResult(offset=0, type="string", data="\x00\x01"),
        R2ByteSearchResult(offset=256, type="string", data="\x00\x01"),
    ]

    for result, ref in zip(results, refs):
        assert result == ref


@pytest.mark.parametrize("test_bin", test_bins)
def test_seek_instructions(test_bin: str, datadir: Path) -> None:
    src_file = str(datadir / test_bin)
    r2 = r2pipe.open(src_file)
    r2.cmd("e asm.arch=x86")
    r2.cmd("e asm.bits=32")

    with R2Seeker(r2) as seeker:
        results = seeker.seek_instructions("push ss")

    refs = [
        R2Instruction(offset=22, len=1, code="push ss"),
        R2Instruction(offset=278, len=1, code="push ss"),
    ]
    for result, ref in zip(list(results), refs):
        assert result == ref
