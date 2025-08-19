; InterceptSuite Standard Edition NSIS Installer
!include "MUI2.nsh"
!include "WinVer.nsh"
!include "x64.nsh"
!include "FileFunc.nsh"

!define APP_NAME "InterceptSuite Standard"
; Version will be passed from build script via /DAPP_VERSION=x.x.x
!ifndef APP_VERSION
    !define APP_VERSION "1.0"
!endif
!define APP_PUBLISHER "InterceptSuite"
!define APP_EXE "InterceptSuite.exe"
!define APP_UNINST "Uninstall.exe"

; Build paths
!define BUILD_DIR "..\..\..\bin\Release\net9.0\win-x64\publish"
!define ICON_FILE "..\..\..\logo.ico"

; Registry keys
!define REG_UNINSTALL "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APP_NAME}"
!define REG_APP "Software\${APP_PUBLISHER}\${APP_NAME}"

; Installer settings
Name "${APP_NAME} ${APP_VERSION}"
OutFile "InterceptSuite-Standard-${APP_VERSION}-Setup.exe"
InstallDir "$LOCALAPPDATA\${APP_NAME}"
InstallDirRegKey HKCU "${REG_APP}" "InstallPath"
RequestExecutionLevel user
SetCompressor lzma

; Modern UI configuration
!define MUI_ABORTWARNING
!define MUI_ICON "${ICON_FILE}"
!define MUI_UNICON "${ICON_FILE}"

; Installer pages
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "..\..\..\..\..\LICENSE"
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!define MUI_FINISHPAGE_RUN "$INSTDIR\${APP_EXE}"
!insertmacro MUI_PAGE_FINISH

; Uninstaller pages
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

; Languages
!insertmacro MUI_LANGUAGE "English"

; Main installation section
Section "Main Application" SecMain
    SectionIn RO

    SetOutPath "$INSTDIR"

    ; Main application (single self-contained executable)
    File "${BUILD_DIR}\${APP_EXE}"

    ; Our custom C library (not embedded, still needed as external DLL)
    SetOutPath "$INSTDIR\resource"
    File "${BUILD_DIR}\resource\Intercept.dll"

    ; Application icon
    SetOutPath "$INSTDIR"
    File "${ICON_FILE}"

    ; Create uninstaller
    WriteUninstaller "$INSTDIR\${APP_UNINST}"

    ; Registry entries
    WriteRegStr HKCU "${REG_APP}" "InstallPath" "$INSTDIR"
    WriteRegStr HKCU "${REG_UNINSTALL}" "DisplayName" "${APP_NAME}"
    WriteRegStr HKCU "${REG_UNINSTALL}" "DisplayVersion" "${APP_VERSION}"
    WriteRegStr HKCU "${REG_UNINSTALL}" "Publisher" "${APP_PUBLISHER}"
    WriteRegStr HKCU "${REG_UNINSTALL}" "UninstallString" "$INSTDIR\${APP_UNINST}"
    WriteRegDWORD HKCU "${REG_UNINSTALL}" "NoModify" 1
    WriteRegDWORD HKCU "${REG_UNINSTALL}" "NoRepair" 1

    ; Create desktop shortcut
    CreateShortcut "$DESKTOP\${APP_NAME}.lnk" "$INSTDIR\${APP_EXE}"

    ; Create start menu shortcut
    CreateDirectory "$SMPROGRAMS\${APP_PUBLISHER}"
    CreateShortcut "$SMPROGRAMS\${APP_PUBLISHER}\${APP_NAME}.lnk" "$INSTDIR\${APP_EXE}"
SectionEnd

; Uninstaller
Section "Uninstall"
    Delete "$INSTDIR\${APP_EXE}"
    Delete "$INSTDIR\logo.ico"
    Delete "$INSTDIR\${APP_UNINST}"

    ; Remove our custom DLL from resource folder
    Delete "$INSTDIR\resource\Intercept.dll"

    RMDir "$INSTDIR\resource"
    RMDir "$INSTDIR"

    Delete "$DESKTOP\${APP_NAME}.lnk"
    Delete "$SMPROGRAMS\${APP_PUBLISHER}\${APP_NAME}.lnk"
    RMDir "$SMPROGRAMS\${APP_PUBLISHER}"

    DeleteRegKey HKCU "${REG_UNINSTALL}"
    DeleteRegKey HKCU "${REG_APP}"
SectionEnd
