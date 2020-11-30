import glob
import json
import os
from dataclasses import asdict
from pathlib import Path
from typing import List

import pytest
import r2pipe

from r2pyapi import R2Surface

test_bins: List[str] = glob.glob(
    os.path.join(os.path.abspath(os.path.splitext(__file__)[0]), "*.exe")
) + glob.glob(os.path.join(os.path.abspath(os.path.splitext(__file__)[0]), "*.out"))


@pytest.mark.parametrize("test_bin", test_bins)
def test_imports(test_bin: str, datadir: Path) -> None:
    src_file = str(datadir / test_bin)
    ref_file = test_bin.split(".")[0] + "_imports.json"
    r2 = r2pipe.open(src_file)

    r2_surf = R2Surface(r2)

    with open(ref_file, "r") as fin:
        refs = json.loads(fin.read())

    for data, ref in zip(r2_surf.imports, refs):
        assert asdict(data) == ref


@pytest.mark.parametrize("test_bin", test_bins)
def test_exports(test_bin: str, datadir: Path) -> None:
    src_file = str(datadir / test_bin)
    ref_file = test_bin.split(".")[0] + "_exports.json"
    r2 = r2pipe.open(src_file)

    r2_surf = R2Surface(r2)

    with open(ref_file, "r") as fin:
        refs = json.loads(fin.read())

    for data, ref in zip(r2_surf.exports, refs):
        assert asdict(data) == ref


@pytest.mark.parametrize("test_bin", test_bins)
def test_sections(test_bin: str, datadir: Path) -> None:
    src_file = str(datadir / test_bin)
    ref_file = test_bin.split(".")[0] + "_sections.json"
    r2 = r2pipe.open(src_file)

    r2_surf = R2Surface(r2)

    with open(ref_file, "r") as fin:
        refs = json.loads(fin.read())

    for data, ref in zip(r2_surf.sections, refs):
        assert asdict(data) == ref


@pytest.mark.parametrize("test_bin", test_bins)
def test_functions(test_bin: str, datadir: Path) -> None:
    src_file = str(datadir / test_bin)
    ref_file = test_bin.split(".")[0] + "_functions.json"
    r2 = r2pipe.open(src_file)

    r2_surf = R2Surface(r2)

    with open(ref_file, "r") as fin:
        refs = json.loads(fin.read())

    for data, ref in zip(r2_surf.functions, refs):
        data_as_dict = {
            key: value for key, value in asdict(data).items() if value is not None
        }
        assert data_as_dict == ref


@pytest.mark.parametrize("test_bin", test_bins)
def test_core(test_bin: str, datadir: Path) -> None:
    src_file = str(datadir / test_bin)
    ref_file = test_bin.split(".")[0] + "_core.json"
    r2 = r2pipe.open(src_file)

    r2_surf = R2Surface(r2)

    with open(ref_file, "r") as fin:
        ref = json.loads(fin.read())

    r2_surf.core.file = os.path.basename(r2_surf.core.file)

    assert asdict(r2_surf.core) == ref


@pytest.mark.parametrize("test_bin", test_bins)
def test_bin(test_bin: str, datadir: Path) -> None:
    src_file = str(datadir / test_bin)
    ref_file = test_bin.split(".")[0] + "_bin.json"
    r2 = r2pipe.open(src_file)

    r2_surf = R2Surface(r2)

    with open(ref_file, "r") as fin:
        ref = json.loads(fin.read())

    assert {key: value for key, value in asdict(r2_surf.bin).items() if value is not None} == ref

@pytest.mark.parametrize("test_bin", test_bins)
def test_entry_point(test_bin: str, datadir: Path) -> None:
    src_file = str(datadir / test_bin)
    ref_file = test_bin.split(".")[0] + "_entry_point.json"
    r2 = r2pipe.open(src_file)

    r2_surf = R2Surface(r2)

    with open(ref_file, "r") as fin:
        ref = json.loads(fin.read())

    assert asdict(r2_surf.entry_point) == ref
