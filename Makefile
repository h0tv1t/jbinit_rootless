SHELL := /usr/bin/env bash

.PHONY: all
all: ramdisk.dmg

jbinit: src/jbinit.c
	xcrun -sdk iphoneos clang -Os -e__dyld_start -Wl,-dylinker -Wl,-dylinker_install_name,/usr/lib/dyld -nostdlib -static -Wl,-fatal_warnings -Wl,-dead_strip -Wl,-Z --target=arm64-apple-ios12.0 -std=gnu17 -flto -ffreestanding -U__nonnull -nostdlibinc -fno-stack-protector src/jbinit.c src/printf.c -o jbinit
	mv jbinit com.apple.dyld
	ldid -S com.apple.dyld
	mv com.apple.dyld jbinit

jbloader: src/jbloader.c ent.xml
	xcrun -sdk iphoneos clang -arch arm64 -Os src/jbloader.c -o jbloader -pthread -Wall -Wextra -funsigned-char -Wno-unused-parameter -DLOADER_DMG_PATH=\"/private/var/palera1n.dmg\" -DLOADER_CHECKSUM=\"$(shell shasum -a 512 loader.dmg | cut -d' ' -f1)\" -DLOADER_SIZE=$(shell stat -f%z loader.dmg)L
	ldid -Sent.xml jbloader

jb.dylib: src/jb.c
	xcrun -sdk iphoneos clang -arch arm64 -Os -Wall -Wextra -Wno-unused-parameter -shared src/jb.c -o jb.dylib
	ldid -S jb.dylib

binpack.dmg: binpack
	rm -f ./binpack.dmg
	sudo mkdir -p binpack/Applications
	sudo hdiutil create -size 8m -layout NONE -format UDZO -imagekey zlib-level=9 -srcfolder ./binpack -fs HFS+ ./binpack.dmg

loader.dmg: loader.ipa
	rm -rf Payload
	unzip loader.ipa
	sudo hdiutil create -size 128m -layout NONE -format ULFO -uid 0 -gid 0 -srcfolder ./Payload -fs HFS+ loader.dmg

upload-loader: loader.dmg
	cat loader.dmg | inetcat 7777

ramdisk.dmg: jbinit jbloader jb.dylib binpack.dmg
	rm -f ramdisk.dmg
	sudo rm -rf ramdisk
	mkdir -p ramdisk
	mkdir -p ramdisk/{binpack,jbin,fs/{gen,orig}}
	mkdir -p ramdisk/{Applications,bin,cores,dev,Developer,Library,private,sbin,System,usr/lib}
	mkdir -p ramdisk/{.ba,.mb}
	cp -a binpack.dmg ramdisk
	ln -s private/etc ramdisk/etc
	ln -s private/var ramdisk/var
	ln -s private/var/tmp ramdisk/tmp
	touch ramdisk/.file
	chmod 000 ramdisk/.file
	chmod 700 ramdisk/{.ba,.mb}
	ln -s /jbin/jbloader ramdisk/sbin/launchd
	mkdir -p ramdisk/usr/lib
	cp jbinit ramdisk/usr/lib/dyld
	cp jb.dylib jbloader ramdisk/jbin
	sudo gchown -R 0:0 ramdisk
	sudo hdiutil create -size 3m -layout NONE -format UDRW -uid 0 -gid 0 -srcfolder ./ramdisk -fs HFS+ ./ramdisk.dmg

clean:
	rm -f jbinit launchd jb.dylib ramdisk.dmg binpack.dmg jbloader
	sudo rm -rf ramdisk
	rm -f ramdisk.img4

.PHONY: all clean
