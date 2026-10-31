"""The walkthrough notebook runs clean, end to end, on the embedded control plane.

Every cell asserts its own outcome, so executing the notebook is the test. It needs no
services, so it runs everywhere the embedded tests do. The checked-in outputs are not
touched: the executed copy is discarded.
"""

from __future__ import annotations

from pathlib import Path

import pytest

nbformat = pytest.importorskip("nbformat")
nbclient = pytest.importorskip("nbclient")
pytest.importorskip("ipykernel")

NOTEBOOK = Path(__file__).resolve().parents[2] / "examples" / "e2e-notebook"


def test_every_cell_runs_and_asserts_clean() -> None:
    nb = nbformat.read(NOTEBOOK / "customer_walkthrough.ipynb", as_version=4)
    client = nbclient.NotebookClient(
        nb, kernel_name="python3", timeout=180, resources={"metadata": {"path": str(NOTEBOOK)}}
    )
    client.execute()  # raises CellExecutionError, naming the cell, on the first failure
    errors = [
        output
        for cell in nb.cells
        if cell.cell_type == "code"
        for output in cell.get("outputs", [])
        if output.get("output_type") == "error"
    ]
    assert errors == []
