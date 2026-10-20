"""Engine shared by the CLI and the GUI. It never prints: front-ends render the events it emits.

input -> hash (1-2 algorithms, one read) -> analyzer -> duplicates -> reports
  `--------------- every step appended to the hash-chained audit log ----------'
"""

from .run import RunConfig, RunSummary, run

__all__ = ["RunConfig", "RunSummary", "run"]
