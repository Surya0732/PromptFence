"""Top-level convenience runner for PromptFence security benchmarks."""

from __future__ import annotations

import sys
from app.evaluation.cli import main

if __name__ == "__main__":
    sys.exit(main())
