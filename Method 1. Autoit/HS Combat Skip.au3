Global Const $hNTDLL = DllOpen("ntdll.dll")
Global Const $hKERNEL32 = DllOpen("kernel32.dll")
Global Const $hIPHLPAPI = DllOpen("iphlpapi.dll")
Global Const $hPSAPI = DllOpen("psapi.dll")
Global Const $hWTSAPI32 = DllOpen("wtsapi32.dll")
Global $aTCPArray

Global $iIsAdmin = IsAdmin()
If Not $iIsAdmin  Then
   MsgBox(0, "Hearthstone Battle Skip", "Failed to get admin privalages")
   Exit
EndIf

HotKeySet("{F5}", "_DropHearthstone")

While 1
   Sleep(100)
WEnd

Func _DropHearthstone()
   $ret = _CV_GetConnections($aTCPArray)
   if $ret Then
	  Return 1
   EndIf

   Local $closedcon = False
   For $x=0 to UBound($aTCPArray) -1
	  Local $name = $aTCPArray[$x][0]
	  Local $remoteport = $aTCPArray[$x][4]
	  If $name == "Hearthstone.exe" And $remoteport == "3724" Then
		 _CV_DisableConnectionSimple($aTCPArray[$x][1], $aTCPArray[$x][2], $aTCPArray[$x][3], $aTCPArray[$x][4])
		 Return 0
	  EndIf
   Next

   ;didnt close connection
   MsgBox(0, "Hearthstone Battle Skip", "Failed to find connection, you are not in a match, or your game is already over.")
EndFunc

Func _CV_GetExtendedTcpTable()

	Local $aCall = DllCall($hIPHLPAPI, "dword", "GetExtendedTcpTable", _
			"ptr*", 0, _
			"dword*", 0, _
			"int", 1, _ ; 1, sort in ascending order
			"dword", 2, _ ; AF_INET4
			"dword", 5, _ ; TCP_TABLE_OWNER_PID_ALL
			"dword", 0)

	If @error Then
		Return SetError(1, 0, 0)
	EndIf

	If $aCall[0] <> 122 Then ; ERROR_INSUFFICIENT_BUFFER
		Return SetError(2, 0, 0)
	EndIf

	Local $iSize = $aCall[2]

	Local $tByteStructure = DllStructCreate("byte[" & $iSize & "]")

	$aCall = DllCall($hIPHLPAPI, "dword", "GetExtendedTcpTable", _
			"ptr", DllStructGetPtr($tByteStructure), _
			"dword*", $iSize, _
			"int", 1, _ ; 1, sort in ascending order
			"dword", 2, _ ; AF_INET4
			"dword", 5, _ ; TCP_TABLE_OWNER_PID_ALL
			"dword", 0)

	If @error Or $aCall[0] Then
		Return SetError(3, 0, 0)
	EndIf

	Local $tMIB_TCPTABLE_OWNER_PID_DWORDS = DllStructCreate("dword[" & Ceiling($iSize / 4) & "]", DllStructGetPtr($tByteStructure))

	Local $iTCPentries = DllStructGetData($tMIB_TCPTABLE_OWNER_PID_DWORDS, 1)

	#cs
		$tMIB_TCPROW_OWNER_PID = DllStructCreate("dword State;" & _
		"dword LocalAddr;" & _
		"dword LocalPort;" & _
		"dword RemoteAddr;" & _
		"dword RemotePort;" & _
		"dword OwningPid")
	#ce

	Local $aTCPTable[$iTCPentries + 1][9] = [["Process Name            ", "Local IP", "Local Port", "Remote IP", "Remote port", "Connection state", "PID", "Full Path", "User Name"]]

	Local $aState[12] = ["CLOSED", "LISTENING", "SYN_SENT", "SYN_RCVD", "ESTABLISHED", "FIN_WAIT1", "FIN_WAIT2", "CLOSE_WAIT", "CLOSING", "LAST_ACK", "TIME_WAIT", "DELETE_TCB"]

	Local $aProcesses = _CV_ProcessList()

	Local $iOffset
	Local $iIP

	TCPStartup()

	For $i = 1 To $iTCPentries

		$iOffset = ($i - 1) * 6 + 1 ; going thru array of dwords

		$aTCPTable[$i][5] = $aState[DllStructGetData($tMIB_TCPTABLE_OWNER_PID_DWORDS, 1, $iOffset + 1) - 1]

		$iIP = DllStructGetData($tMIB_TCPTABLE_OWNER_PID_DWORDS, 1, $iOffset + 2)

		If $iIP = 16777343 Then
			$aTCPTable[$i][1] = "localhost (127.0.0.1)"
		ElseIf $iIP = 0 Then
			$aTCPTable[$i][1] = "Any local address"
		Else
			$aTCPTable[$i][1] = BitOR(BinaryMid($iIP, 1, 1), 0) & "." & BitOR(BinaryMid($iIP, 2, 1), 0) & "." & BitOR(BinaryMid($iIP, 3, 1), 0) & "." & BitOR(BinaryMid($iIP, 4, 1), 0)
			$aTCPTable[$i][1] = $aTCPTable[$i][1]
		EndIf

		$aTCPTable[$i][2] = Dec(Hex(BinaryMid(DllStructGetData($tMIB_TCPTABLE_OWNER_PID_DWORDS, 1, $iOffset + 3), 1, 2)))
		$aTCPTable[$i][2] &= ""

		If DllStructGetData($tMIB_TCPTABLE_OWNER_PID_DWORDS, 1, $iOffset + 1) < 3 Then
			$aTCPTable[$i][4] = "-"
			$aTCPTable[$i][3] = "-"
		Else
			$iIP = DllStructGetData($tMIB_TCPTABLE_OWNER_PID_DWORDS, 1, $iOffset + 4)
			$aTCPTable[$i][3] = BitOR(BinaryMid($iIP, 1, 1), 0) & "." & BitOR(BinaryMid($iIP, 2, 1), 0) & "." & BitOR(BinaryMid($iIP, 3, 1), 0) & "." & BitOR(BinaryMid($iIP, 4, 1), 0)
			$aTCPTable[$i][4] = Dec(Hex(BinaryMid(DllStructGetData($tMIB_TCPTABLE_OWNER_PID_DWORDS, 1, $iOffset + 5), 1, 2)))
			$aTCPTable[$i][4] &= ""
		EndIf

		$aTCPTable[$i][6] = DllStructGetData($tMIB_TCPTABLE_OWNER_PID_DWORDS, 1, $iOffset + 6)
		If Not $aTCPTable[$i][6] Then
			$aTCPTable[$i][6] = "-"
			$aTCPTable[$i][0] = "System Idle Process"
			$aTCPTable[$i][7] = "-"
			$aTCPTable[$i][8] = "SYSTEM"
		Else
			For $j = 1 To $aProcesses[0][0]
				If $aProcesses[$j][1] = $aTCPTable[$i][6] Then
					$aTCPTable[$i][0] = $aProcesses[$j][0]
					$aTCPTable[$i][7] = _CV_GetPIDFileName($aProcesses[$j][1])
					If Not $aTCPTable[$i][7] Then
							$aTCPTable[$i][7] = "-"
					EndIf
					If Not $aTCPTable[$i][0] Then $aTCPTable[$i][0] = $aProcesses[$j][0]
					$aTCPTable[$i][8] = $aProcesses[$j][2]
					If Not $aTCPTable[$i][8] Then
						If $iIsAdmin Then
							$aTCPTable[$i][8] = "SYSTEM"
						Else
							$aTCPTable[$i][8] = "-"
						EndIf
					EndIf
					ExitLoop
				EndIf
			Next
		EndIf

	Next

	TCPShutdown()

	Return $aTCPTable

EndFunc   ;==>_CV_GetExtendedTcpTable

Func _CV_ProcessList()
	Local $aCall = DllCall($hWTSAPI32, "bool", "WTSEnumerateProcessesW", _
			"handle", 0, _
			"dword", 0, _
			"dword", 1, _
			"ptr*", 0, _
			"dword*", 0)
	If @error Or Not $aCall[0] Then
		Local $aProcesses = ProcessList()
		ReDim $aProcesses[$aProcesses[0][0]][3]
		For $i = 1 To UBound($aProcesses) - 1
			$aProcesses[$i][2] = "-"
		Next
		Return SetError(1, 0, $aProcesses)
	EndIf
	Local $tWTS_PROCESS_INFO
	Local $pString, $iStringLen
	Local $aOut[$aCall[5] + 1][3]
	$aOut[0][0] = $aCall[5]
	For $i = 1 To $aCall[5]
		$tWTS_PROCESS_INFO = DllStructCreate("dword SessionId;" & _
				"dword ProcessId;" & _
				"ptr ProcessName;" & _
				"ptr UserSid", _
				$aCall[4] + ($i - 1) * DllStructGetSize($tWTS_PROCESS_INFO)) ; looping thru structures
		$pString = DllStructGetData($tWTS_PROCESS_INFO, "ProcessName")
		$iStringLen = _CV_PtrStringLenW($pString)
		$aOut[$i][0] = DllStructGetData(DllStructCreate("wchar[" & $iStringLen + 1 & "]", $pString), 1)
		If $aOut[$i][0] = "System" Then $aOut[$i][0] = "" ; & " (System)"
		$aOut[$i][1] = DllStructGetData($tWTS_PROCESS_INFO, "ProcessId")
		$aOut[$i][2] = ""
	Next
	DllCall($hWTSAPI32, "none", "WTSFreeMemory", "ptr", $aCall[4])
	Return $aOut
EndFunc   ;==>_CV_ProcessList

Func _CV_PtrStringLenW($pString)
	Local $aCall = DllCall($hKERNEL32, "dword", "lstrlenW", "ptr", $pString)
	If @error Then Return SetError(1, 0, 0)
	Return $aCall[0]
EndFunc   ;==>_CV_PtrStringLenW

Func _CV_GetConnections(ByRef $aTCPArray)
	$aTCPArray = _CV_GetExtendedTcpTable()
	$iExtendedTCP = 1
	If @error Then
	  MsgBox(0, "Hearthstone Battle Skip", "Failed to get list of TCP Connections error: " & @error)
	  Return 1
	EndIf
	Return 0
EndFunc   ;==>_CV_GetConnections

Func _CV_DisableConnectionSimple($LocIP, $LocPort, $RemIP, $RemPort)

   ;local ip, local port, remote ip, remote port

;~ Local $aArrayOfData = StringSplit($sConnectionInfoString, "|", 3)
	Local $tMIB_TCPROW = DllStructCreate("dword State;" & _
			"dword LocalAddr;" & _
			"dword LocalPort;" & _
			"dword RemoteAddr;" & _
			"dword RemotePort")
	DllStructSetData($tMIB_TCPROW, "State", 12) ; MIB_TCP_STATE_DELETE_TCB


	Local $aIP
	Local $iIPLocal
		 $aIP = StringRegExp($LocIP, "\((.*?)\)", 3)
		 If Not @error Then
			 $LocIP = $aIP[0]
		 EndIf
		 Local $aIPLocal = StringSplit($LocIP, ".")
		 $iIPLocal = Dec(Hex($aIPLocal[4], 2) & Hex($aIPLocal[3], 2) & Hex($aIPLocal[2], 2) & Hex($aIPLocal[1], 2))
	DllStructSetData($tMIB_TCPROW, "LocalAddr", $iIPLocal)


	Local $iPortLocal
	Local $aPortLocal = StringRegExp($LocPort, "\A\d{1,5}", 3)
	If @error Then
		$iPortLocal = 0
	Else
		$iPortLocal = Dec(Hex(BinaryMid(Number($aPortLocal[0]), 1, 2)))
	EndIf
	DllStructSetData($tMIB_TCPROW, "LocalPort", $iPortLocal)


	Local $iIPRemote
   $aIP = StringRegExp($RemIP, "\((.*?)\)", 3)
   If Not @error Then
	   $RemIP = $aIP[0]
   EndIf
   Local $aIPRemote = StringSplit($RemIP, ".")
   $iIPRemote = Dec(Hex($aIPRemote[4], 2) & Hex($aIPRemote[3], 2) & Hex($aIPRemote[2], 2) & Hex($aIPRemote[1], 2))
	DllStructSetData($tMIB_TCPROW, "RemoteAddr", $iIPRemote)


	Local $iPortRemote
	Local $aPortRemote = StringRegExp($RemPort, "\A\d{1,5}", 3)
	If @error Then
		$iPortRemote = 0
	Else
		$iPortRemote = Dec(Hex(BinaryMid(Number($aPortRemote[0]), 1, 2)))
	EndIf
	DllStructSetData($tMIB_TCPROW, "RemotePort", $iPortRemote)
	Local $aCall = DllCall($hIPHLPAPI, "dword", "SetTcpEntry", "ptr", DllStructGetPtr($tMIB_TCPROW))
	If @error Or $aCall[0] Then Return SetError(2, 0, 0)
	Return 1
 EndFunc   ;==>_CV_DisableConnection

Func _CV_GetPIDFileName($iPID)
	Local $aCall = DllCall($hKERNEL32, "ptr", "OpenProcess", _
			"dword", 1040, _ ; PROCESS_QUERY_INFORMATION|PROCESS_VM_READ
			"int", 0, _
			"dword", $iPID)
	If @error Or Not $aCall[0] Then Return SetError(1, 0, "")
	Local $hProcess = $aCall[0]
	$aCall = DllCall($hPSAPI, "dword", "GetModuleFileNameExW", _
			"handle", $hProcess, _
			"ptr", 0, _
			"wstr", "", _
			"dword", 32767)
	If @error Or Not $aCall[0] Then
		DllCall($hKERNEL32, "bool", "CloseHandle", "handle", $hProcess)
		Return SetError(2, 0, "")
	EndIf
	Local $sFilename = $aCall[3]
	DllCall($hKERNEL32, "bool", "CloseHandle", "handle", $hProcess)
	Return $sFilename
EndFunc   ;==>_CV_GetPIDFileName

