# About

This tool demonstrates various remote dll injection methods.

# Usage

Usage: `inject [pid] [dll_file] [CRT|STC|QUA|NQAT|NQATE] [R|LW|LA]`

#### Injection types
* CRT   - CreateRemoteThread injection (default)
* STC   - SetThreadContext injection
* QUA   - QueueUserApc injection
* NQAT  - NtQueueApcThread injection
* NQATE - NtQueueApcThreadEx injection

#### Loader types
* R     - Reflective loader (default)
* LW    - LoadLibraryW loader
* LA    - LoadLibraryA loader

# Build

Use Visual Studio 2015 to build the solution.
	
License
=======

Licensed under a 3 clause BSD license, please see LICENSE.txt for details.
