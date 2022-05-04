<img align="left" src="https://raw.githubusercontent.com/LunarResearch/KernelExplorer/main/KernelExplorer/KernelExplorer/Fsociety.ico" width="256" height="256">

#  KernelExplorer

**Researching NT Kernel & System Objects (Win32 API)**

Interactive Services Detection

System Authorization with Highest Rights

Switching Desktops & Sessions Utility

Remote Processes Controlling using the Service Account Interceptor

## Downloading

- [GitHub Release](https://github.com/LunarResearch/KernelExplorer/releases)

- [Google Drive](https://drive.google.com/drive/folders/1GlQJTfRSdYs_pRMnrmkJeqlgupmfiHia)
    - Please rename `KernelExplorer.exe_RenameMe` to `KernelExplorer.exe`, and `UI0Detect.exe_RenameMe` to `UI0Detect.exe`.
    - Microsoft's Independent Developer Policy is a hard method in [SmartScreen](https://habr.com/ru/post/505194/).
    - The browser adds an NTFS-stream named [Zone.Identifier](https://docs.microsoft.com/en-us/archive/blogs/askcore/alternate-data-streams-in-ntfs) to the file, where it places a link from where the file was downloaded. SmartScreen swears at files with this NTFS stream.

## System requirements

Windows Vista or higher, only 64-bit.

Recommended to use with Windows 10 or Windows 11.

## Features

* Works under an account `NT AUTHORITY\\SYSTEM`
* Access to protected objects of the operating system kernel.
* Management of processes and services of the operating system.
* Access to the terminal session (SessionId 0), Workstations and Desktops.
* 100% [Free Software](https://www.gnu.org/philosophy/free-sw.en.html) ([GPL v3](https://www.gnu.org/licenses/gpl-3.0.en.html))


## Building the projects and using

Requires Visual Studio (2022 or later).

Load the `KernelExplorer.sln`, `LdrModuleEx.sln`, `LdrModuleGUI.sln`, `NtAuth.sln`, `NtAuthHR.sln`, `RpcInterceptor.sln` and `UI0Return.sln` solutions if you prefer building the project using Visual Studio.

You can download the free [Visual Studio Community](https://www.visualstudio.com/vs/community/) to build the KernelExplorer source code.

### Additional utilities:
1. [Explorer++](https://github.com/derceg/explorerplusplus)
2. [Process Hacker](https://github.com/processhacker/processhacker)
3. [WinObjEx64](https://github.com/hfiref0x/WinObjEx64)
4. [FireDaemon ZeroInput](https://kb.firedaemon.com/support/solutions/articles/4000123189)

*For correct operation, it is necessary to observe the structure of folders and subfolders*

<img align="left" src="https://raw.githubusercontent.com/LunarResearch/KernelExplorer/main/folder_struct.png" width="284" height="170">
