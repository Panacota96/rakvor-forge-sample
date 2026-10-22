"""Engine shared by the CLI and the GUI. It never prints: front-ends render the events it emits.

input -> hash (1-2 algorithms, one read) -> analyzer -> duplicates -> reports
  `--------------- every step appended to the hash-chained audit log ----------'
"""

# This tool's place in a shared case folder (see docs/case-folder.md). The reference rv-hashinv is the INTAKE
# tool ("intake": it registers evidence); tools scaffolded from it are ANALYSIS tools ("analysis": they verify
# every item against the registry). The scaffold flips this one constant together with "case_role" in .forge.json.
CASE_ROLE = "intake"

from .run import RunConfig, RunSummary, run  # noqa: E402 - CASE_ROLE must exist before run.py reads it

__all__ = ["CASE_ROLE", "RunConfig", "RunSummary", "run"]
