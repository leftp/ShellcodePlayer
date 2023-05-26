# ShellcodePlayer

## Description

ShellcodePlayer is a versatile tool for configuring loaders for shellcode payloads. It allows you to dynamically generate loaders from templates and customize them according to your needs. The project provides options to add one or multiple sandbox bypass strategies and payload execution controls. It also enables you to remove specific strings from the output file, ensuring flexibility and variability in the generated payloads.
With ShellcodePlayer, you can create templates for different stages of shellcode execution, allowing you to easily generate payloads with distinct behaviors. The tool supports various options for memory execution control, providing fine-grained control over the execution of the payload in memory.
By default, the project encrypts the shellcode using AES with the target's domain name. You can add multiple domains, resulting in multiple encrypted shellcodes embedded in the loader. Upon execution, the loader attempts to decrypt the shellcode using the domain obtained on the host through WinAPI.

## IOCs (Indicators of Compromise)
The user has control over IOCs (Indicators of Compromise) and can add them to a new dictionary and use it during compilation.

## String Obfuscation
To make a string less noticeable in the bin file, enclose the string in <obf\>"string_here"<ob_end>.

## Configuration Management
The user can save configurations used to build loaders and load them during runtime from JSON configuration files.

## Execution Flow
The execution flow of the loader is as follows:
1. Sandbox Bypass Strategies
2. Payload Execution Control Strategies
3. QueryDomain
4. AESDecrypt fast/medium/slow Shellcodes
5. ProcessCreate (Creates a new process for EACH shellcode)
6. ProcessOpen
7. AllocMemory (Allocates memory in the EACH remote proces)
8. WriteMemory
9. ProtectMemory
10. ExecuteMemory

Note: The project is designed to allow red team operators to add three shellcodes (fast, medium, and slow) for each C2 channel.

## Disclaimer
The code is provided "as is" without any warranties or guarantees. It is intended for educational and research purposes only. The usage of this code for any illegal activities is strictly prohibited. The responsibility for any consequences of using this code lies solely with the user.
