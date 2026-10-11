# SAFIX — Static Analyzer for FIX
# Copyright (C) 2026 BoringLLM
#
# This program is free software: you can redistribute it and/or modify it under the terms of the
# GNU Affero General Public License as published by the Free Software Foundation, either version 3
# of the License, or (at your option) any later version. See the LICENSE file for the full text.
# A separate commercial license is also available; see the NOTICE file.
#
# This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
# without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
"""SAFIX — Static Analyzer for FIX.

A security scanner for the FIX trading protocol: parse FIX logs, reconstruct session and
order state, and raise true-positive-aware alerts for protocol attacks, abuse, and
policy/regulatory violations.
"""

__version__ = "0.1.0"
