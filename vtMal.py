from __future__ import print_function
from unicorn import *
from unicorn.x86_const import *
import pefile
import os
import re
import sys
from ctypes import *
import struct
import socket
from keystone import * # using keystone as assembler
from capstone import * # using capstone as disassembler
IMAGE_FILE_MACHINE_I386 = 0x014c
IMAGE_FILE_MACHINE_IA64 = 0x0200

# fake win32 api environment
HOOK_BASE = 0xff00000
EACH_DLL_PAGE_SIZE = 0x1000
HOOK_BASE_MAX = HOOK_BASE + HOOK_BASE * (0x100);

class malBox(object):
	'''
	win32_dict = {
		'Kernel32.dll' : {
			'dllName' : 'Kernel32.dll',
			'dllBase' : 0xff00000,
			'apiDict' : {
				'OpenProcess' : 0xff00001,
				'CreateProcessA' : 0xff00002, ...
			}
		}, ...
	}'''

	win32_dict = {}

	init_exe_file_ok = False
	is_x86_machine = True
	log = True
	log_emu = False
	log_api = False

	def printLog(self, text): 
		if self.log: print(text)
	def printApi(self, text): 
		if self.log_api: print(text)
	def printEmu(self, text): 
		if self.log_emu: print(text)

	# -------------------- sandbox win32 API internal --------------------
	def repair_fake_teb(self):
		# fake tib/peb
		# refer https://en.wikipedia.org/wiki/Win32_Thread_Information_Block
		# http://www.youngroe.com/2015/08/01/Debug/peb-analysis/
		TEB_BASE = 0
		PEB_BASE = TEB_BASE + 0x1000

		class teb_struct(Structure):
			_fields_ = [
				("seh_frame", c_uint32),         # fs:00h <-- important
				("stack_base", c_uint32),        # fs:04h high addr
				("stack_limit", c_uint32),       # fs:08h low addr
				("sub_sys_tib", c_uint32),       # fs:0ch keep null
				("fiber_data", c_uint32),        # fs:10h keep null
				("arbitary_data", c_uint32),     # fs:14h keep null
				("addr_of_teb", c_uint32),       # fs:18h <-- important
				("envment_pointer", c_uint32),   # fs:1ch keep null
				("process_id", c_uint32),        # fs:20h process id
				("curr_thread_id", c_uint32),    # fs:24h current thread id
				("act_rpc_handle", c_uint32),    # fs:28h keep null
				("addr_of_tls", c_uint32),       # fs:2ch don't care
				("proc_env_block", c_uint32)     # fs:30h <-- important
												 # ... too much item
			]
		teb = teb_struct(
			-1,                                  # fs:00h
			self.stack_base,                     # fs:04h
			self.stack_base - self.stack_size,   # fs:08h
			0,                                   # fs:0ch
			0,                                   # fs:10h
			0,                                   # fs:14h
			TEB_BASE,                            # fs:18h (teb base)
			0,                                   # fs:1ch
			0xdeadbeef,                          # fs:20h (process id)
			0xdeadbeef,                          # fs:24h (current thread id)
			0,                                   # fs:28h
			0,                                   # fs:2ch
			PEB_BASE                             # fs:3ch (peb base)
		)
		teb_payload = bytes(teb)
		self.uc.mem_map(TEB_BASE, 1024 * 1024 * 4)
		self.uc.mem_write(TEB_BASE, teb_payload)
		self.uc.reg_write(UC_X86_REG_FS, TEB_BASE)

	def win32_get_api_name_by_addr(self, addr):
		if not (HOOK_BASE <= addr <= HOOK_BASE_MAX):
			return None
		for _, dll_img in self.win32_dict.items():
			if dll_img['dllBase'] <= addr <= dll_img['dllLimt']:
				return dll_img['apiDict'].get(addr)
		return None
	# --------------------------------------------------------------------
	

	indent_count = 1
	@staticmethod
	def print_memory(uc, addr, size, self):
		sp = uc.reg_read(UC_X86_REG_ESP) # stack pointer
		args = struct.unpack('<IIIIII', uc.mem_read(sp, 24))

		CODE = uc.mem_read(addr, size)
		md = Cs(CS_ARCH_X86, CS_MODE_32)
		for i in md.disasm(bytes(CODE), addr):
			self.printEmu("%x:%s%s\t%s" %(i.address, self.indent_count * '\t', i.mnemonic, i.op_str))

			if self.indent_count < 5:
				if i.mnemonic == 'call':
					self.printEmu('')
					self.indent_count += 1
				elif i.mnemonic == 'ret':
					self.printEmu('')
					self.indent_count -= 1

	# emulator hook
	@staticmethod
	def hook_code(uc, addr, size, self):
		sp = uc.reg_read(UC_X86_REG_ESP) # stack pointer
		args = struct.unpack('<IIIIII', uc.mem_read(sp, 24))
		retn_addr = args[0]
		caller_addr = args[0] - 6 # size of 'call ds: xxxx' = 6 in x86

		# program counter is point to win32 api?
		if  HOOK_BASE <= addr <= HOOK_BASE_MAX:
			api_name = self.win32_get_api_name_by_addr(addr)
			if api_name == None:
				self.printApi('[!] %x: executed bad API addr @ %x' % (caller_addr, addr))
			else:
				self.printApi('\n[+] %x: invoked win32 API %s' % (caller_addr, api_name))
				self.printApi('[+] -------------------- stack trace --------------------')
				for i in range(1, 5):
					strval = uc.mem_read(args[i], 30).decode('utf8', errors='ignore').strip('\x00')
					self.printApi('>>> args_%i(%x) --> %.8x | %s' % (i, sp + 4 * i, args[i], strval))
				self.printApi('---------------------------------------------------------\n')
		else:
			malBox.print_memory(uc, addr, size, self)


	def __init__(self, file_name, log = True, log_emu = True, log_api = False):
		self.log = log
		self.log_emu = log_emu
		self.log_api = log_api

		self.printLog('''
                                                                          
                                88  88888888ba                            
                                88  88      "8b                           
                                88  88      ,8P                           
88,dPYba,,adPYba,   ,adPPYYba,  88  88aaaaaa8P'   ,adPPYba,  8b,     ,d8  
88P'   "88"    "8a  ""     `Y8  88  88""""""8b,  a8"     "8a  `Y8, ,8P'   
88      88      88  ,adPPPPP88  88  88      `8b  8b       d8    )888(     
88      88      88  88,    ,88  88  88      a8P  "8a,   ,a8"  ,d8" "8b,   
88      88      88  `"8bbdP"Y8  88  88888888P"    `"YbbdP"'  8P'     `Y8  
                                                                          
                                                                          ''')
		try:
			self.printLog('[+] malbox :: init -> %s' % file_name)
			with open(file_name, 'rb') as f: self.pe_data = f.read()
		except:
			self.printLog('\t[!] read file failure (file is missing or path incorrect?)')
			return
		else:
			self.printLog('\t[+] file data ready')

		self.pe = pefile.PE(data = self.pe_data)
		if not self.pe.is_exe():
			self.printLog('\t[!] this file is not a PE format file')
			return

		# detect machine type
		self.init_exe_file_ok = False
		if self.pe.FILE_HEADER.Machine == IMAGE_FILE_MACHINE_I386:
			self.is_x86_machine = True
			self.stack_base = 0x00300000
			self.stack_size = 0x00100000
			self.stack_red_zone = 0x1000
			self.init_exe_file_ok = True
			self.printLog('\t[+] detect x86 type machine')
			
		elif self.pe.FILE_HEADER.Machine == self.IMAGE_FILE_MACHINE_IA64:
			self.is_x86_machine = False
			self.stack_base = 0xffffffff00000000
			self.stack_size = 0x0000000000006000
			self.stack_red_zone = 0x1000
			self.printLog('\t[+] detect x86_64 type machine')
			self.printLog('\t[！] sorry, x86_64 not supported :(')
			
		else: printLog('\t[!] unknwon type arch :(')

		# basic PE info 
		self.image_base = self.pe.OPTIONAL_HEADER.ImageBase
		self.addr_entry = self.image_base + self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
		self.size_of_image = self.pe.OPTIONAL_HEADER.SizeOfImage
		self.printLog('\t[+] malbox is ready :)\n')

	def run(self):
		self.uc = None
		self.printLog('[+] malbox :: run ')
		if not self.init_exe_file_ok:
			self.printLog('\t[!] malbox still not ready yet?')
			return

		if self.is_x86_machine: self.uc = Uc(UC_ARCH_X86, UC_MODE_32)
		else: self.uc = Uc(UC_ARCH_X64, UC_MODE_64)

		# mapping image into process memory (e.g. section, image header, etc)
		self.uc.mem_map(self.image_base, self.size_of_image) 
		mapped_image = self.pe.get_memory_mapped_image(ImageBase=self.image_base)
		self.uc.mem_write(self.image_base, mapped_image)
		self.printLog('\t[+] finish mapping section into process')

		# repair import descriptor (import address table)
		self.printLog("\t[+] Listing the imported symbols")
		for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
			curr_dll_dict = {}
			curr_dll_dict['apiDict'] = {}
			curr_dll_dict['dllName'] = entry.dll.decode()
			curr_dll_dict['dllBase'] = HOOK_BASE + len(self.win32_dict) * EACH_DLL_PAGE_SIZE
			curr_dll_dict['dllLimt'] = curr_dll_dict['dllBase'] + EACH_DLL_PAGE_SIZE - 1

			self.uc.mem_map(curr_dll_dict['dllBase'], EACH_DLL_PAGE_SIZE)
			self.uc.mem_write(curr_dll_dict['dllBase'], b'\xC3' * EACH_DLL_PAGE_SIZE) # ret
			self.printLog('\t%x - %s' % (curr_dll_dict['dllBase'], curr_dll_dict['dllName']))

			for imp in entry.imports:
				curr_api_name = imp.name.decode()
				curr_api_addr = curr_dll_dict['dllBase'] + len(curr_dll_dict['apiDict'])
				self.uc.mem_write(imp.address, struct.pack('<I', curr_api_addr))
				curr_dll_dict['apiDict'][curr_api_addr] = curr_api_name
				self.printLog("\t\t[%x] -> %s @ %x" % (imp.address, curr_api_name, curr_api_addr))
			self.win32_dict[curr_dll_dict['dllName']] = curr_dll_dict

		# deal with x86 call frame
		self.uc.mem_map(0, 1024 * 1024 * 4) 
		self.uc.reg_write(UC_X86_REG_ESP, self.stack_base + self.stack_size - 4)
		self.printLog('\t[+] allocate stack @ %x' % (self.stack_base + self.stack_size - 4))
		
		self.uc.hook_add(UC_HOOK_CODE, malBox.hook_code, self)

		# execute entry point
		try:
			self.printEmu("[+] emulator execute ... ")
			self.uc.emu_start(self.addr_entry, 0)

		except UcError as e:
			self.printEmu("ERROR: %s" % e)
		self.printEmu("[+] emulator done. ")
	# ...

malBox('ConsoleApplication1.exe', log = True, log_emu = True, log_api = True).run()
