# [Turbo Campaign](https://www.fidelissecurity.com/resources/turbo-campaign-featuring-derusbi-64-bit-linux)
In the summer of 2015, Fidelis Cybersecurity had the opportunity to analyze a Derusbi malware sample used as part of a campaign we’ve labeled Turbo, for the associated kernel module that was deployed. Derusbi has been widely covered and associated with Chinese threat actors. This malware has been reported to have been used in high profile breaches like the ones at Wellpoint/Anthem, VAE Inc, USIS and Mitsubishi Heavy Industries. Every one of these campaigns involved a Windows version of Derusbi.

The sample we uncover is the Linux 64-bit version.

You can find the full report [here](https://www.fidelissecurity.com/resources/turbo-campaign-featuring-derusbi-64-bit-linux)

### Hash Research
We crafted a yara rule based on the beacon strings found in the Linux 64-bit Derusbi and detected the following twenty-five (25) Windows version of Derusbi samples.  These files include 32-bit and 64-bit files, Dynamic Link Library (DLL) samples, and EXE samples where majority of the detected files were compiled in 2011. These results helped us trace a stronger correlations between known Windows version of Derusbi with the Linux version of the report. The following are MD5 hashes of the samples detected:
 
	eeb636886ecc9ff3623d10f1efcf3c09 | 3a76b081fc7964ab239f26d356c59692 | 6802c21d3d0d80084bf93413dc0c23a7
	d3ad90010c701e731835142fabb6bfcc | 449521ce87ed0111dcb0d4beff85064d | f942f98cff86f8fcde7eb0c2f465be7a
	59cb505d1636119f2881caa14bf42326 | f99e10c9d269b0596bfe8ac91ec62fe9 | 3a27de4fb6e2c524e883c40a43da554e
	3804d23ddb141c977b98c2885953444f | 76767ef2d2bb25eba45203f0d2e8335b | 6d620d5a903f0d714c30565a9bfdce8f
	1e113600e397226c3e09c9c628d8ab95 | 1ae0c39cb9684652c017161f8a5aca78 | 6ec15a34f058176be4e4685eda9a5cfc
	3dec6df39910045791ee697f461baaba | 70508f3b0af558833609151b368d3cc5 | a1fb51343f3724e8b683a93f2d42127b
	72662c61ae8ef7566a945f648e9d4dd8 | 128c17340cb5add26bf60dfe2af37700 | 837b6b1601e0fa99f28657dee244223b
	8c0cf5bc1f75d71879b48a286f6befcf | bc32ecb75624a7bec7a901e10c195307 | 75b3ccd4d3bfb56b55a46fba9463d282
	3c973c1ad37dae0443a078dba685c0ea
 
 
 
### Yara rule
 
The following Yara rules will detect the 64-bit Linux version, rootkit module and Windows variants of the Derusbi malware covered in the paper:
 
	rule apt_nix_elf_derusbi
	{
	               strings:
	                              $ = "LxMain"
	                              $ = "execve"
	                              $ = "kill"
	                              $ = "cp -a %s %s"
	                              $ = "%s &"
	                              $ = "dbus-daemon"
	                              $ = "--noprofile"
	                              $ = "--norc"
	                              $ = "TERM=vt100"
	                              $ = "/proc/%u/cmdline"
	                              $ = "loadso"
	                              $ = "/proc/self/exe"
	                              $ = "Proxy-Connection: Keep-Alive"
	                              $ = "Connection: Keep-Alive"
	                              $ = "CONNECT %s"
	                              $ = "HOST: %s:%d"
	                              $ = "User-Agent: Mozilla/4.0"
	                              $ = "Proxy-Authorization: Basic %s"
	                              $ = "Server: Apache"
	                              $ = "Proxy-Authenticate"
	                              $ = "gettimeofday"
	                              $ = "pthread_create"
	                              $ = "pthread_join"
	                              $ = "pthread_mutex_init"
	                              $ = "pthread_mutex_destroy"
	                              $ = "pthread_mutex_lock"
	                              $ = "getsockopt"
	                              $ = "socket"
	                              $ = "setsockopt"
	                              $ = "select"
	                              $ = "bind"
	                              $ = "shutdown"
	                              $ = "listen"
	                              $ = "opendir"
	                              $ = "readdir"
	                              $ = "closedir"
	                              $ = "rename"
	 
	               condition:
	                              (uint32(0) == 0x4464c457f) and (all of them)
	}
	rule apt_nix_elf_derusbi_kernelModule
	{
	               strings:
	                              $ = "__this_module"  
	                              $ = "init_module"     
	                              $ = "unhide_pid"      
	                              $ = "is_hidden_pid"   
	                              $ = "clear_hidden_pid"
	                              $ = "hide_pid"
	                              $ = "license"
	                              $ = "description"
	                              $ = "srcversion="
	                              $ = "depends="
	                              $ = "vermagic="
	                              $ = "current_task"
	                              $ = "sock_release"
	                              $ = "module_layout"
	                              $ = "init_uts_ns"
	                              $ = "init_net"
	                              $ = "init_task"
	                              $ = "filp_open"
	                              $ = "__netlink_kernel_create"
	                              $ = "kfree_skb"
	 
	               condition:
	                              (uint32(0) == 0x4464c457f) and (all of them)
	}
	rule apt_nix_elf_Derusbi_Linux_SharedMemCreation
	{
	               strings:
	                              $byte1 = { B6 03 00 00 ?? 40 00 00 00 ?? 0D 5F 01 82 }
	               condition:
	                              (uint32(0) == 0x464C457F) and (any of them)
	}
	 
	rule apt_nix_elf_Derusbi_Linux_Strings
	{
	               strings:
	                               $a1 = "loadso" wide ascii fullword
	                               $a2 = "\nuname -a\n\n" wide ascii
	                               $a3 = "/dev/shm/.x11.id" wide ascii
	                               $a4 = "LxMain64" wide ascii nocase
	                               $a5 = "# \\u@\\h:\\w \\$ " wide ascii
	                               $b1 = "0123456789abcdefghijklmnopqrstuvwxyz" wide
	                               $b2 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ" wide
	                                $b3 = "ret %d" wide fullword
	                               $b4 = "uname -a\n\n" wide ascii
	                               $b5 = "/proc/%u/cmdline" wide ascii
	                                $b6 = "/proc/self/exe" wide ascii
	                                $b7 = "cp -a %s %s" wide ascii
	                                $c1 = "/dev/pts/4" wide ascii fullword
	                               $c2 = "/tmp/1408.log" wide ascii fullword
	               condition:
	                              uint32(0) == 0x464C457F and
	                              ((1 of ($a*) and 4 of ($b*)) or
	                              (1 of ($a*) and 1 of ($c*)) or
	                              2 of ($a*) or
	                              all of ($b*))
	}
	 
	rule apt_win_exe_trojan_derusbi
	{
	               strings:
	                              $sa_1 = "USB" wide ascii
	                              $sa_2 = "RAM" wide ascii
	                              $sa_3 = "SHARE" wide ascii
	                              $sa_4 = "HOST: %s:%d"
	                              $sa_5 = "POST"
	                              $sa_6 = "User-Agent: Mozilla"
	                              $sa_7 = "Proxy-Connection: Keep-Alive"
	                              $sa_8 = "Connection: Keep-Alive"
	                              $sa_9 = "Server: Apache"
	                              $sa_10 = "HTTP/1.1"
	                              $sa_11 = "ImagePath"
	                              $sa_12 = "ZwUnloadDriver"
	                              $sa_13 = "ZwLoadDriver"
	                              $sa_14 = "ServiceMain"
	                              $sa_15 = "regsvr32.exe"
	                              $sa_16 = "/s /u" wide ascii
	                              $sa_17 = "rand"
	                              $sa_18 = "_time64"
	                              $sa_19 = "DllRegisterServer"
	                              $sa_20 = "DllUnregisterServer"
	                              $sa_21 = { 8b [5] 8b ?? d3 ?? 83 ?? 08 30 [5] 40 3b [5] 72 } // Decode Driver
	                        
	                              $sb_1 = "PCC_CMD_PACKET"
	                              $sb_2 = "PCC_CMD"
	                              $sb_3 = "PCC_BASEMOD"
	                              $sb_4 = "PCC_PROXY"
	                              $sb_5 = "PCC_SYS"
	                              $sb_6 = "PCC_PROCESS"
	                              $sb_7 = "PCC_FILE"
	                              $sb_8 = "PCC_SOCK"
	                             
	                              $sc_1 = "bcdedit -set testsigning" wide ascii
	                              $sc_2 = "update.microsoft.com" wide ascii
	                              $sc_3 = "_crt_debugger_hook" wide ascii
	                              $sc_4 = "ue8G5" wide ascii
	                             
	                              $sd_1 = "NET" wide ascii
	                              $sd_2 = "\\\\.\\pipe\\%s" wide ascii
	                              $sd_3 = ".dat" wide ascii
	                              $sd_4 = "CONNECT %s:%d" wide ascii
	                              $sd_5 = "\\Device\\" wide ascii
	                             
	                              $se_1 = "-%s-%04d" wide ascii
	                              $se_2 = "-%04d" wide ascii
	                              $se_3 = "FAL" wide ascii
	                              $se_4 = "OK" wide ascii
	                              $se_5 = "2.03" wide ascii
	                              $se_6 = "XXXXXXXXXXXXXXX" wide ascii
	 
	               condition:
	                              (uint16(0) == 0x5A4D) and ( (all of ($sa_*)) or (
	                                             (13 of ($sa_*)) and
	                                                            ( (5 of ($sb_*)) or (3 of ($sc_*)) or (all of ($sd_*)) or
	                                                               ( (1 of ($sc_*)) and (all of ($se_*)) ) ) ) )
	}
	 
