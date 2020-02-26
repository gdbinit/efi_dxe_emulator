EFI DXE Emulator  
An EFI DXE binary emulator based on Unicorn  
Copyright © 2016-2019 Pedro Vilaca. All rights reserved.  
reverser@put.as - https://reverse.put.as  
Copyright © 2020 Assaf Carlsbad. All rights reserved.  

This is a Windows-centric port of the EFI DXE phase binaries emulator by [Pedro Vilaca](https://github.com/gdbinit/efi_dxe_emulator).  
See [README_ORIG](README_ORIG.md) for more details.

## Building

1. Clone & bootstrap Vcpkg:
```
> git clone https://github.com/Microsoft/vcpkg.git
> cd vcpkg

PS> .\bootstrap-vcpkg.bat
PS> .\vcpkg integrate install
```

2. Install required dependencies:
```
PS> .\vcpkg install capstone[x86] getopt-win32 inih linenoise-ng mman unicorn
```

Note: for 64-bit builds just append the suffix `:x64-windows` to each package name (e.g. `capstone:x64-windows`).

3. Open `efi_dxe_emulator.sln` in Visual Studio and build it from the IDE.

## Known issues

The Debug version occasionally crashes when returning from `uc_emu_start`. Prefer using the Release version in the meantime.
