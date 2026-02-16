#!/usr/bin/env python3
"""
Network Throughput Bottleneck Analyzer
Run the Flask development server.

Usage:
    python run.py

For production:
    gunicorn -w 4 -b 0.0.0.0:5000 "app:create_app()"
"""

import os
from dotenv import load_dotenv

load_dotenv()

from app import create_app

app = create_app()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_DEBUG", "true").lower() == "true"
    app.run(host="0.0.0.0", port=port, debug=debug)
