<img align="left" src="https://raw.githubusercontent.com/LunarResearch/KernelExplorer/main/KernelExplorer/KernelExplorer/Fsociety.ico" width="256" height="256">

##  KernelExplorer

Researching NT Kernel & System Objects (Win32 API).

Access to protected objects of the operating system kernel.

Management of processes and services of the operating system.

Access to the terminal session (SessionId 0), Workstations and Desktops.

[Project Download](https://drive.google.com/drive/folders/1GlQJTfRSdYs_pRMnrmkJeqlgupmfiHia)

## System requirements

Windows Vista or higher, only 64-bit.

Recommended to used Windows 10 or Windows 11.

## Features

* 100% [Free Software](https://www.gnu.org/philosophy/free-sw.en.html) ([GPL v3](https://www.gnu.org/licenses/gpl-3.0.en.html))


## Building the project and using

Requires Visual Studio (2019 or later).

Load the `KernelExplorer.sln`, `LdrModuleEx.sln`, `LdrModuleGUI.sln`, `NtAuth.sln`, `NtAuthHR.sln`, `RpcInterceptor.sln` and `UI0Return.sln` solutions if you prefer building the project using Visual Studio.

You can download the free [Visual Studio Community](https://www.visualstudio.com/vs/community/) to build the KernelExplorer source code.

After compilation place the executables in the following order:

1. Main folder: KernelExplorer.exe, LdrModuleEx.dll, LdrModuleGUI.dll, RpcInterceptor.dll
2. Subfolders:
3. NtAuthorization: NtAuth.dll, NtAuthHR.dll
4. UI0Detect: UI0Detect.exe, UI0Return.dll
5. UI0Input: fdui0input.cat, FDUI0Input.inf, FDUI0Input.sys
6. Utilities:
7. Explorer: all files [Explorer++](https://github.com/derceg/explorerplusplus)
8. ProcessHacker: all files of [Process Hacker](https://github.com/processhacker/processhacker)
9. WinObjEx: all files of [WinObjEx64](https://github.com/hfiref0x/WinObjEx64)
