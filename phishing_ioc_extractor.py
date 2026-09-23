#!/usr/bin/env python3
"""Run phishtriage straight from a checkout, without installing it.

    python phishing_ioc_extractor.py mail.eml

is equivalent to `phish-triage mail.eml` after `pip install .`
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "src"))

from phishtriage.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
