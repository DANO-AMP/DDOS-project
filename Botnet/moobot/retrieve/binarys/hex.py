#!/usr/bin/python
# -*- coding: utf-8

import sys, sys, os, re, binascii

binarys = [
	"dlr.arm:arm.hex", 		#arm
	"dlr.arm7:arm7.hex", 	#arm7
	"dlr.m68k:m68k.hex", 	#m68k
	"dlr.mips:mips.hex", 	#mips
	"dlr.mpsl:mpsl.hex", 	#mpsl
	"dlr.ppc:ppc.hex", 		#ppc
	"dlr.sh4:sh4.hex", 		#sh4
	"dlr.spc:spc.hex", 		#spc
	"dlr.x86:x86.hex" 		#x86
	]

def insert_slashx(string, every=2):
    return '\\x'.join(string[i:i+every] for i in xrange(0, len(string), every))

def splitCount(s, count):
     return [''.join(x) for x in zip(*[list(s[z::count]) for z in range(count)])]

for bin in binarys:
	try:
		Input = bin.split(":")[0]
		Output = bin.split(":")[1]
		hexify = '\\x'+insert_slashx(binascii.hexlify(open(Input).read()))
		echoify = "echo -en \'"+'\' >>lno\necho -en \''.join(splitCount(hexify,(64*2))) + '\' >>lno'
		f = open(Output, "w")
		f.write(echoify)
		f.close()
	except:
		pass