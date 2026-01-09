JFS SIEM Agent - One-Click Service Installer (WinSW)

Files in this folder:
- JFS_SIEM_Agent_Enhanced_ServiceFix.exe      (the agent EXE)
- JFSSIEMAgentService.exe                     (WinSW.NET4.exe renamed)
- JFSSIEMAgentService.xml                     (service config)
- install_agent_service.bat                   (one-click install; auto UAC)
- uninstall_agent_service.bat                 (one-click uninstall; auto UAC)

How to install on an agent PC:
1) Copy this entire folder to the agent PC (e.g. Desktop\JFS_SIEM_Agent_Service)
2) Double-click install_agent_service.bat
3) Click Yes on the UAC prompt

Logs:
C:\ProgramData\JFS_SIEM_Agent\service\logs\

Service name:
JFSSIEMAgent
