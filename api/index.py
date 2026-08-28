import sys
import os

current_dir = os.path.dirname(os.path.abspath(__file__))
root_dir = os.path.dirname(current_dir)
backend_dir = os.path.join(root_dir, 'email-threat-platform', 'backend')

if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from app.main_v3 import app

