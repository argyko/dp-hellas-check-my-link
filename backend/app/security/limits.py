from __future__ import annotations
import os

MAX_REQUEST_BODY_BYTES = int(os.getenv('MAX_REQUEST_BODY_BYTES', '16384'))
MAX_URL_LENGTH = int(os.getenv('MAX_URL_LENGTH', '4096'))
MAX_SCAN_TIMEOUT_SECONDS = int(os.getenv('MAX_SCAN_TIMEOUT_SECONDS', '180'))
MAX_CONCURRENT_SCANS = int(os.getenv('MAX_CONCURRENT_SCANS', '2'))
