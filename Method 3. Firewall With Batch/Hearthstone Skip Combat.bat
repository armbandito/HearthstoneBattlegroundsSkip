@echo off
if not DEFINED IS_MINIMIZED set IS_MINIMIZED=1 && start "" /min "%~dpnx0" %* && exit
	:: Create the new rule
	netsh advfirewall firewall add rule name="Hearthstone Skip Combat" dir=out action=block protocol=TCP remoteport=1119

	:: Check if rule is indeed created
	netsh advfirewall firewall show rule name="Hearthstone Skip Combat" > NUL 2>&1
	IF ERRORLEVEL 1 (
			ECHO Failed to create rule!
			pause
			exit
	)
	::Wait 3 seconds
	timeout /T 3
	ECHO Removing rule

	::Delete Rule
	netsh advfirewall firewall delete rule name="Hearthstone Skip Combat"
exit