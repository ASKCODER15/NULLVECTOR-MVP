"""NullVector backend package.

Putting the repository root on ``sys.path`` is what lets the backend import the
scanner engine in ``ai/`` (docs/PROJECT_CONTEXT.md §7). Without it, running
uvicorn from ``backend/`` makes ``ai`` unimportable and every scanner route
fails at import time.
"""

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
