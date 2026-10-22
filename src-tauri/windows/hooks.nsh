LangString HP_FIREWALL_DETAIL ${LANG_CZECH} "Nastavuji firewall pravidlo HomeProxy pouze pro privátní místní síť"
LangString HP_FIREWALL_DETAIL ${LANG_ENGLISH} "Configuring the HomeProxy firewall rule for the private local network only"
LangString HP_FIREWALL_FAILED ${LANG_CZECH} "HomeProxy nemohl bezpečně omezit přístup ve Windows Firewall. Instalace byla zastavena."
LangString HP_FIREWALL_FAILED ${LANG_ENGLISH} "HomeProxy could not safely restrict access in Windows Firewall. Installation has stopped."
LangString HP_AUTOSTART_DETAIL ${LANG_CZECH} "Zapínám automatické spuštění HomeProxy po přihlášení"
LangString HP_AUTOSTART_DETAIL ${LANG_ENGLISH} "Enabling automatic HomeProxy startup after sign-in"
LangString HP_AUTOSTART_FAILED ${LANG_CZECH} "HomeProxy se nepodařilo zaregistrovat pro automatické spuštění. Instalace byla zastavena."
LangString HP_AUTOSTART_FAILED ${LANG_ENGLISH} "HomeProxy could not be registered for automatic startup. Installation has stopped."
LangString HP_AUTOSTART_REMOVE ${LANG_CZECH} "Vypínám automatické spuštění HomeProxy"
LangString HP_AUTOSTART_REMOVE ${LANG_ENGLISH} "Disabling automatic HomeProxy startup"
LangString HP_FIREWALL_REMOVE ${LANG_CZECH} "Odebírám firewall pravidla HomeProxy"
LangString HP_FIREWALL_REMOVE ${LANG_ENGLISH} "Removing HomeProxy firewall rules"

!macro NSIS_HOOK_POSTINSTALL
  DetailPrint "$(HP_FIREWALL_DETAIL)"
  nsExec::ExecToLog 'netsh advfirewall firewall delete rule name="Klidna sit proxy (cz.klidnasit.desktop)"'
  Pop $0
  nsExec::ExecToLog 'netsh advfirewall firewall delete rule name="HomeProxy proxy (cz.klidnasit.desktop)"'
  Pop $0
  nsExec::ExecToLog 'netsh advfirewall firewall add rule name="HomeProxy proxy (cz.klidnasit.desktop)" dir=in action=allow program="$INSTDIR\klidna-sit.exe" enable=yes profile=private protocol=TCP remoteip=localsubnet'
  Pop $0
  StrCmp $0 "0" firewall_rule_added
  SetErrorLevel 1
  MessageBox MB_ICONSTOP|MB_OK "$(HP_FIREWALL_FAILED)"
  Abort
firewall_rule_added:
  DetailPrint "$(HP_AUTOSTART_DETAIL)"
  ClearErrors
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Run" "HomeProxy" '$\"$INSTDIR\klidna-sit.exe$\" --autostart'
  IfErrors autostart_registration_failed autostart_registered
autostart_registration_failed:
  nsExec::ExecToLog 'netsh advfirewall firewall delete rule name="HomeProxy proxy (cz.klidnasit.desktop)"'
  Pop $0
  SetErrorLevel 1
  MessageBox MB_ICONSTOP|MB_OK "$(HP_AUTOSTART_FAILED)"
  Abort
autostart_registered:
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  DetailPrint "$(HP_AUTOSTART_REMOVE)"
  DeleteRegValue HKLM "Software\Microsoft\Windows\CurrentVersion\Run" "HomeProxy"
  DetailPrint "$(HP_FIREWALL_REMOVE)"
  nsExec::ExecToLog 'netsh advfirewall firewall delete rule name="HomeProxy proxy (cz.klidnasit.desktop)"'
  Pop $0
  nsExec::ExecToLog 'netsh advfirewall firewall delete rule name="Klidna sit proxy (cz.klidnasit.desktop)"'
  Pop $0
!macroend
