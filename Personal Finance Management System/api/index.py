# api/index.py – Vercel serverless entry point
import sys
import os

# Ensure the project root is in the Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from main import app

# Vercel expects the WSGI app to be named "app"
# It is automatically exported here for the @vercel/python runtime
