@echo off
if defined ProgramFiles(x86) (
	@echo Windows 64 bit detected
	mkdir target\packfolder
	copy ..\packfolder.exe target\
	cargo build --release --features=packui
	pause
	exit
) else (
	@echo Windows 32 bit detected
	SET VCPKG_ROOT=C:\vcpkg
	SET VCPKG_DEFAULT_TRIPLET=x86-windows-static
	SET LIBCLANG_PATH=C:\Program Files\LLVM\bin
	SET VCPKG_TARGET_ARCHITECTURE=x86

	copy packfolder.exe target\
	copy ..\packfolder.exe target\
	mkdir target
	mkdir target\packfolder

	del /F /Q libs\virtual_display\src\lib.rs
	copy libs\virtual_display\src\lib-win7.rs libs\virtual_display\src\lib.rs

	rustup default stable-i686-pc-windows-msvc
	cargo build --release --features=packui --target i686-pc-windows-msvc
	pause
)






