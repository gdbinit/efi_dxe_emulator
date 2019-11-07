EFI DXE Emulator  
An EFI DXE binary emulator based on Unicorn  
Copyright © 2016-2019 Pedro Vilaca. All rights reserved.  
reverser@put.as - https://reverse.put.as

This is an EFI DXE phase binaries emulator based on [Unicorn](https://www.unicorn-engine.org).

Reference blogpost explaining how it works: [Crafting an EFI Emulator and Interactive Debugger](https://reverse.put.as/2019/10/29/crafting-an-efi-emulator/).

It allows to run EFI DXE binaries inside a Unicorn virtual nachine with a basic interactive debugger that allows to step and interact with the EFI code.

It works by implementing basic EFI Boot and Runtime services. Not every service is yet implemented, such as services to load and locate other binaries. This can be done with extra work, since the core code to load binaries already exists, although it needs to be modularized.

Can be used to easier reverse some EFI binaries that don't interact with hardware or graphical EFI interface. 
This tool was created to reverse engineer and analyse the EFI binaries related to Apple's firmware password reset described in this blog post, https://reverse.put.as/2016/06/25/apple-efi-firmware-passwords-and-the-scbo-myth/. So some stuff is configured/hardcoded for this specific goal (the sample ini file is configured with the required binaries).

The debugger is still pretty basic but allows to view and modify registers and memory, step into calls or over them, and breakpoints. Unicorn has some limitations regarding this, such as problems changing the EFLAGS register inside a hook. The hook implementation for breakpoints also has some limitations. These are due to the JIT used by Unicorn/QEMU.

The debugger command line parser is pretty crude and definitely needs serious work to improve it. It works pretty well if we know what we are doing. It's based on gdb/gdbinit commands.

Even with all its limitations this is a pretty useful tool for reversing some EFI binaries, improving a lot the reverse engineering process from a static analysis only (for us who don't have 6k JTAG based EFI debuggers).

It's also a nice showcase of Unicorn potential and limitations. With further development it could be expanded to fuzzing and vulnerability discovery in firmware world.

To retrieve the code and its dependencies:

```bash
git clone --recursive 'https://github.com/gdbinit/efi_dxe_emulator.git'
```

No Makefile available, only a Xcode project but the code should easily compile in other Unix OSes with minor modifications if necessary.

I have included a sample.ini file, the two target EFI binaries extracted from a MacBook Pro 8,2 model, and the SCBO file that was available around Internet. There is no NVRAM dump because I need to sanitize the one I have used. You will need to modify the paths inside the sample.ini file.

Enjoy,  
fG!
