@echo off
:: ShieldScan — GUI Launcher
:: Automatically relaunches as Administrator if needed.
:: NOTE: gui.py was quarantined by antivirus; running gui_restored.py instead.
:: Once antivirus is cleared, rename gui_restored.py to gui.py and revert this file.

title ShieldScan

:: Check if already running as admin
net session >nul 2>&1
if %errorlevel% == 0 (
    :: Already admin — launch directly
    python "%~dp0gui_restored.py" %*
) else (
    :: Relaunch with elevation — open a new cmd window as admin
    runas /user:Administrator "cmd /c python \"%~dp0gui_restored.py\""
)
