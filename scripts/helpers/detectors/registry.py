"""Registry of all decision-tree detectors."""

from __future__ import annotations

from collections.abc import Callable

from detectors import aiw, cfw, epw, grcw, hgw, iw, kvcw, ptw, sew, udw
from detectors.models import Label, WorkflowContext

DetectorFn = Callable[[WorkflowContext], list[Label]]

ALL_DETECTORS: list[tuple[str, DetectorFn]] = [
    ("IW", iw.detect),
    ("PTW", ptw.detect),
    ("SEW", sew.detect),
    ("KVCW", kvcw.detect),
    ("AIW", aiw.detect),
    ("CFW", cfw.detect),
    ("EPW", epw.detect),
    ("UDW", udw.detect),
    ("GRCW", grcw.detect),
    ("HGW", hgw.detect),
]


def detect_all(ctx: WorkflowContext) -> list[Label]:
    out: list[Label] = []
    for _name, fn in ALL_DETECTORS:
        out.extend(fn(ctx))
    return out
