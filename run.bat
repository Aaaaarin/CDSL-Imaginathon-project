@echo off
cd /d %~dp0
python -m uvicorn backend.main:app --port 8740
