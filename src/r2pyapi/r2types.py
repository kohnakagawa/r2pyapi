from dataclasses import dataclass
from typing import Dict, List, Optional, Union, cast


@dataclass()
class R2Core:
    type: str
    file: str
    fd: int
    size: int
    humansz: str
    iorw: bool
    mode: str
    block: int
    format: str


@dataclass()
class R2Bin:
    arch: str
    baddr: int
    binsz: int
    bintype: str
    bits: int
    canary: bool


@dataclass()
class R2FileInfo:
    core: R2Core
    bin: R2Bin


@dataclass()
class R2Section:
    vaddr: int
    paddr: int
    size: int
    vsize: int
    name: str
    perm: str


@dataclass()
class R2Export:
    name: str
    flagname: str
    realname: str
    ordinal: int
    bind: str
    size: int
    type: str
    vaddr: int
    paddr: int
    is_imported: bool


@dataclass(init=False)
class R2Import:
    ordinal: int
    bind: str
    type: str
    name: str
    libname: Optional[str]
    plt: int

    def __init__(self, raw: Dict[str, Union[str, int]]) -> None:
        self.ordinal = cast(int, raw["ordinal"])
        self.bind = cast(str, raw["bind"])
        self.type = cast(str, raw["type"])
        self.name = cast(str, raw["name"])
        self.libname = cast(str, raw["libname"]) if "libname" in raw.keys() else None
        self.plt = cast(int, raw["plt"])


@dataclass()
class R2Ref:
    addr: int
    type: str
    at: int


@dataclass()
class R2LocalVarRef:
    base: str
    offset: int


@dataclass(init=False)
class R2LocalVar:
    name: str
    kind: str
    type: str
    ref: R2LocalVarRef

    def __init__(self, raw: dict) -> None:
        self.name = raw["name"]
        self.kind = raw["kind"]
        self.type = raw["type"]
        self.ref = R2LocalVarRef(raw["ref"]["base"], raw["ref"]["offset"])


@dataclass()
class R2RegVar:
    name: str
    kind: str
    type: str
    ref: str


@dataclass(init=False)
class R2Function:
    offset: int
    name: str
    size: int
    is_pure: bool
    realsz: int
    noreturn: bool
    stackframe: int
    calltype: str
    cost: int
    cc: int
    bits: int
    type: int
    nbbs: int
    edges: int
    ebbs: int
    signature: str
    minbound: int
    maxbound: int
    callrefs: Optional[List[R2Ref]]
    datarefs: List[int]
    codexrefs: Optional[List[R2Ref]]
    dataxrefs: List[int]
    indegree: int
    outdegree: int
    nlocals: int
    nargs: int
    bpvars: Optional[List[R2LocalVar]]
    spvars: Optional[List[R2LocalVar]]
    regvars: Optional[List[R2RegVar]]
    difftype: Optional[str]

    def __init__(self, raw: dict) -> None:
        self.offset = raw["offset"]
        self.name = raw["name"]
        self.size = raw["size"]
        self.is_pure = raw["is-pure"] == "true"
        self.realsz = raw["realsz"]
        self.noreturn = raw["noreturn"]
        self.stackframe = raw["stackframe"]
        self.calltype = raw["calltype"]
        self.cost = raw["cost"]
        self.cc = raw["cc"]
        self.bits = raw["bits"]
        self.type = raw["type"]
        self.nbbs = raw["nbbs"]
        self.edges = raw["edges"]
        self.ebbs = raw["ebbs"]
        self.signature = raw["signature"]
        self.minbound = raw["minbound"]
        self.maxbound = raw["maxbound"]
        if "callrefs" in raw.keys():
            self.callrefs = [R2Ref(**entry) for entry in raw["callrefs"]]
        else:
            self.callrefs = None
        self.datarefs = raw["datarefs"] if "datarefs" in raw.keys() else None
        if "codexrefs" in raw.keys():
            self.codexrefs: List[R2Ref] = [R2Ref(**entry) for entry in raw["codexrefs"]]
        else:
            self.codexrefs = None
        self.dataxrefs = raw["dataxrefs"] if "dataxrefs" in raw.keys() else None
        self.indegree = raw["indegree"]
        self.outdegree = raw["outdegree"]
        self.nlocals = raw["nlocals"] if "nlocals" in raw.keys() else None
        self.nargs = raw["nargs"] if "nargs" in raw.keys() else None
        if "bpvars" in raw.keys():
            self.bpvars = [R2LocalVar(entry) for entry in raw["bpvars"]]
        else:
            self.bpvars = None
        if "spvars" in raw.keys():
            self.spvars = [R2LocalVar(entry) for entry in raw["spvars"]]
        else:
            self.spvars = None
        if "regvars" in raw.keys():
            self.regvars = [R2RegVar(**entry) for entry in raw["regvars"]]
        else:
            self.regvars = None
        if "difftype" in raw.keys():
            self.difftype = raw["difftype"]
        else:
            self.difftype = None


@dataclass()
class R2Instruction:
    offset: int
    len: int
    code: str


@dataclass()
class R2ByteSearchResult:
    offset: int
    type: str
    data: str
