@echo off
cd /d "C:\Users\sleyt\sentinel-oracle"
"C:\Program Files\nodejs\node.exe" dist\index.js > "C:\Users\sleyt\.sentinel-oracle\debug-server.log" 2>&1
