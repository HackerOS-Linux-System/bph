#+feature dynamic-literals
package main

import "core:fmt"
import "core:os"
import "core:strings"
import "core:path/filepath"
import "core:slice"
import "core:encoding/json"
import "core:time"
import "core:bufio"
import "core:io"
import "core:sys/posix"
import "core:c"

foreign import lua_lib "system:lua5.4"

	foreign lua_lib {
		luaL_newstate :: proc () -> rawptr ---
		luaL_openlibs :: proc (L: rawptr) ---
		luaL_loadfilex :: proc (L: rawptr, filename: cstring, mode: cstring) -> i32 ---
		lua_pcallk :: proc (L: rawptr, nargs, nresults, errfunc: i32, ctx: i32, k: rawptr) -> i32 ---
		lua_getfield :: proc (L: rawptr, idx: i32, k: cstring) -> i32 ---
		lua_pushstring :: proc (L: rawptr, s: cstring) ---
		lua_tolstring :: proc (L: rawptr, idx: i32, len: ^uintptr) -> cstring ---
		lua_close :: proc (L: rawptr) ---
		lua_type :: proc (L: rawptr, idx: i32) -> i32 ---
	}

	LUA_TFUNCTION :: i32(6) // From lua.h
	LUA_GLOBALSINDEX :: i32(-10002)

	foreign import system_lib "system:c"

		foreign system_lib {
			environ: ^^c.char
		}

		ToolDoc :: struct {
			name:    string,
			desc:    string,
			example: string,
		}

		main :: proc() {
			if len(os.args) < 2 {
				print_help()
				return
			}
			command := os.args[1]
			args := os.args[2:]
			distro_images := map[string]string {
				"kali"      = "docker.io/kalilinux/kali-rolling:latest",
				"blackarch" = "docker.io/blackarch/blackarch:latest",
			}
			tool_docs := []ToolDoc {
				{"nmap", "Network scanner for discovering hosts and services.", "nmap -sV target_ip"},
				{"metasploit", "Framework for exploiting vulnerabilities.", "msfconsole"},
				{"wireshark", "Packet analyzer for network traffic.", "wireshark"},
				{"aircrack-ng", "Wi-Fi security assessment suite.", "airodump-ng wlan0"},
				{"burpsuite", "Web vulnerability scanner.", "burpsuite"},
				{"john", "Password cracker.", "john hashes.txt"},
				{"hydra", "Online password brute-forcer.", "hydra -l user -P passlist ssh://target"},
				{"nikto", "Web server scanner.", "nikto -h target.com"},
				{"sqlmap", "SQL injection exploiter.", "sqlmap -u target_url"},
				{"maltego", "OSINT visualization tool.", "maltego"},
				{"own-tools", "Custom pentesting tools suite.", "own-tools <subcommand> e.g., port-scan, vuln-check, pass-gen, hash-crack, osint-search"},
			}
			container_name :: proc(distro: string) -> string {
				return strings.concatenate({"bph-", distro})
			}
			home := os.get_env("HOME")
			log_dir := filepath.join({home, ".hackeros", "bph", "logs"})
			plugin_dir := filepath.join({home, ".hackeros", "bph", "plugins"})
			own_tools_path := filepath.join({home, ".hackeros", "bph", "own-tools"})
			os.make_directory(log_dir, 0o755)
			os.make_directory(plugin_dir, 0o755)
			warn_tools := []string{"hydra", "sqlmap", "nikto"}

			// Better error handling: Check Podman access
			if !check_podman_access() {
				fmt.println("\033[31mError: Cannot access Podman. Check permissions or installation.\033[0m")
				return
			}

			switch command {
				case "init":
					if len(args) < 1 {
						fmt.println("\033[31mUsage: bph-backend init <distro> (kali or blackarch)\033[0m")
						return
					}
					distro := args[0]
					if distro not_in distro_images {
						fmt.println("\033[31mUnsupported distro. Use kali or blackarch.\033[0m")
						return
					}
					image := distro_images[distro]
					cmd_args := []string{"distrobox", "create", "--name", container_name(distro), "--image", image}
					exec_command(cmd_args)
				case "enter":
					if len(args) < 1 {
						fmt.println("\033[31mUsage: bph-backend enter <distro>\033[0m")
						return
					}
					distro := args[0]
					if distro not_in distro_images {
						fmt.println("\033[31mUnsupported distro.\033[0m")
						return
					}
					cmd_args := []string{"distrobox", "enter", container_name(distro)}
					exec_command(cmd_args)
				case "run":
					if len(args) < 2 {
						fmt.println("\033[31mUsage: bph-backend run <distro> <tool> [args...]\033[0m")
						return
					}
					distro := args[0]
					if distro not_in distro_images {
						fmt.println("\033[31mUnsupported distro.\033[0m")
						return
					}
					tool := args[1]
					tool_args := args[1:]
					if tool == "own-tools" {
						output := exec_command_with_output(append([]string{own_tools_path}, tool_args[1:]...))
						t := time.now()
						year, month, day := time.date(t)
						date_str := fmt.tprintf("%d-%02d-%02d", year, int(month), day)
						log_file := strings.concatenate({date_str, "_", tool, ".log"})
						full_log := filepath.join({log_dir, log_file})
						os.write_entire_file(full_log, transmute([]u8) output)
						fmt.print(output)
						return
					}
					if slice.contains(warn_tools, tool) {
						fmt.println("\033[33mWarning: Do you have written permission to test this target? (y/n)\033[0m")
						reader: bufio.Reader
						bufio.reader_init(&reader, os.stream_from_handle(os.stdin))
						defer bufio.reader_destroy(&reader)
						byte, _ := bufio.reader_read_byte(&reader)
						if byte != 'y' && byte != 'Y' {
							fmt.println("\033[31mAborting.\033[0m")
							return
						}
					}
					cmd_args := make([]string, 4 + len(tool_args) - 1)
					cmd_args[0] = "distrobox"
					cmd_args[1] = "enter"
					cmd_args[2] = container_name(distro)
					cmd_args[3] = "--"
					copy(cmd_args[4:], tool_args)
					output := exec_command_with_output(cmd_args)
					t := time.now()
					year, month, day := time.date(t)
					date_str := fmt.tprintf("%d-%02d-%02d", year, int(month), day)
					log_file := strings.concatenate({date_str, "_", tool, ".log"})
					full_log := filepath.join({log_dir, log_file})
					os.write_entire_file(full_log, transmute([]u8) output)
					fmt.print(output)
				case "docs":
					if len(args) < 1 {
						fmt.println("\033[31mUsage: bph-backend docs <tool>\033[0m")
						return
					}
					tool_name := args[0]
					for tool in tool_docs {
						if tool.name == tool_name {
							fmt.printf("\033[32m%s: %s\nExample: %s\033[0m\n", tool.name, tool.desc, tool.example)
							if tool_name == "own-tools" {
								fmt.println("\033[32mSubcommands:\nport-scan <target> - Scan ports\nvuln-check <url> - Check basic vulns\npass-gen <length> - Generate password\nhash-crack <hash> - Simple hash cracker\nosint-search <query> - Basic OSINT search\033[0m")
							}
							return
						}
					}
					fmt.println("\033[31mTool not found. Available: nmap, metasploit, wireshark, aircrack-ng, burpsuite, john, hydra, nikto, sqlmap, maltego, own-tools\033[0m")
				case "parse":
					if len(args) < 2 {
						fmt.println("\033[31mUsage: bph-backend parse <tool> <raw_output>\033[0m")
						return
					}
					tool := args[0]
					raw_output := strings.join(args[1:], " ")
					parsed := parse_output(tool, raw_output, plugin_dir)
					fmt.println(parsed)
				case "checklist":
					if len(args) < 1 {
						fmt.println("\033[31mUsage: bph-backend checklist <tool>\033[0m")
						return
					}
					tool := args[0]
					check_pre_attack(tool)
				case "snapshot":
					if len(args) < 3 {
						fmt.println("\033[31mUsage: bph-backend snapshot save/restore <distro> <file>\033[0m")
						return
					}
					mode := args[0]
					distro := args[1]
					file := args[2]
					if distro not_in distro_images {
						fmt.println("\033[31mUnsupported distro.\033[0m")
						return
					}
					cmd_args: []string
					if mode == "save" {
						cmd_args = []string{"podman", "container", "checkpoint", "--export", file, container_name(distro)}
					} else if mode == "restore" {
						cmd_args = []string{"podman", "container", "restore", "--import", file, container_name(distro)}
					} else {
						fmt.println("\033[31mInvalid mode: save or restore\033[0m")
						return
					}
					exec_command(cmd_args)
				case "stealth":
					stealth_info()
				case "report":
					if len(args) < 1 {
						fmt.println("\033[31mUsage: bph-backend report <date> (YYYY-MM-DD)\033[0m")
						return
					}
					date := args[0]
					generate_report(date, log_dir, plugin_dir)
				case "network":
					if len(args) < 2 {
						fmt.println("\033[31mUsage: bph-backend network create <name>\033[0m")
						return
					}
					subcmd := args[0]
					if subcmd == "create" {
						name := args[1]
						cmd_args := []string{"podman", "network", "create", name}
						exec_command(cmd_args)
					} // Add more subcmds like connect etc.
				case "gateway":
					if len(args) < 2 {
						fmt.println("\033[31mUsage: bph-backend gateway start <type> (tor/vpn)\033[0m")
						return
					}
					subcmd := args[0]
					typ := args[1]
					if subcmd == "start" && typ == "tor" {
						exec_command([]string{"podman", "pull", "dperson/torproxy"})
						exec_command([]string{"podman", "run", "-d", "-p", "9050:9050", "--name", "bph-tor-gateway", "dperson/torproxy"})
					}
				case "clean":
					if len(args) < 1 {
						fmt.println("\033[31mUsage: bph-backend clean <distro>\033[0m")
						return
					}
					distro := args[0]
					cmd_args := []string{"distrobox", "enter", container_name(distro), "--", "rm", "-rf", "/var/log/*"}
					exec_command(cmd_args)
				case "detect-sandbox":
					detect_sandbox()
				case "session":
					if len(args) < 3 {
						fmt.println("\033[31mUsage: bph-backend session new/attach <distro> <tool>\033[0m")
						return
					}
					mode := args[0]
					distro := args[1]
					tool := args[2]
					session_name := strings.concatenate({"bph-", tool})
					if mode == "new" {
						exec_command([]string{"tmux", "new-session", "-d", "-s", session_name, fmt.tprintf("distrobox enter %s -- %s", container_name(distro), tool)})
					} else if mode == "attach" {
						exec_command([]string{"tmux", "attach-session", "-t", session_name})
					}
				case "help":
					print_help()
				case:
					fmt.println("\033[31mUnknown command.\033[0m")
					print_help()
			}
		}

		print_help :: proc() {
			fmt.println("\033[32mBackend for BPH - Educational CLI for Pentesting Learning\033[0m")
			fmt.println("\033[33mUsage: bph-backend <command> [args]\033[0m")
			fmt.println("Commands:")
			fmt.println(" init <distro> Create container (distro: kali or blackarch)")
			fmt.println(" enter <distro> Enter container shell")
			fmt.println(" run <distro> <tool> [args] Run tool in container with logging (supports own-tools)")
			fmt.println(" docs <tool> View tool documentation")
			fmt.println(" parse <tool> <raw_output> Parse tool output to JSON")
			fmt.println(" checklist <tool> Run pre-attack checklist")
			fmt.println(" snapshot save/restore <distro> <file> Snapshot container")
			fmt.println(" stealth Run stealth system info gatherer (educational)")
			fmt.println(" report <date> Generate report for session")
			fmt.println(" network create <name> Create isolated network")
			fmt.println(" gateway start <type> Start gateway (tor/vpn)")
			fmt.println(" clean <distro> Clean logs (anti-forensics)")
			fmt.println(" detect-sandbox Educational sandbox detection")
			fmt.println(" session new/attach <distro> <tool> Manage detachable sessions")
			fmt.println(" help Show this help")
			fmt.println("\033[33m\nLearn ethically! Always get permission for testing.\033[0m")
		}

		check_podman_access :: proc() -> bool {
			output := exec_command_with_output([]string{"podman", "--version"})
			return !strings.contains(output, "Error")
		}

		exec_command :: proc(args: []string) {
			if len(args) == 0 {
				return
			}
			full_path := find_full_path(args[0])
			if full_path == "" {
				fmt.printf("\033[31mCommand not found: %s\033[0m\n", args[0])
				return
			}
			defer delete(full_path)
			pid := posix.fork()
			if pid == -1 {
				fmt.println("\033[31mFork failed.\033[0m")
				return
			}
			if pid == 0 {
				c_argv := make([]cstring, len(args) + 1)
				for a, i in args {
					c_argv[i] = cstring(raw_data(a))
				}
				c_argv[len(args)] = nil
				c_full_path := cstring(raw_data(full_path))
				posix.execve(c_full_path, raw_data(c_argv), transmute([^]cstring) environ)
				fmt.println("\033[31mExec failed.\033[0m")
				delete(c_argv)
				posix._exit(1)
			} else {
				status: i32
				posix.waitpid(pid, &status, {})
				if WIFEXITED(status) && WEXITSTATUS(status) != 0 {
					fmt.printf("\033[31mCommand failed with status %d\033[0m\n", WEXITSTATUS(status))
				}
			}
		}

		exec_command_with_output :: proc(args: []string) -> string {
			stdout_fds: [2]posix.FD
			if posix.pipe(&stdout_fds) != .OK {
				return "\033[31mPipe failed.\033[0m"
			}
			stdout_r := stdout_fds[0]
			stdout_w := stdout_fds[1]
			stderr_fds: [2]posix.FD
			if posix.pipe(&stderr_fds) != .OK {
				return "\033[31mPipe failed.\033[0m"
			}
			stderr_r := stderr_fds[0]
			stderr_w := stderr_fds[1]
			full_path := find_full_path(args[0])
			if full_path == "" {
				return fmt.tprintf("\033[31mCommand not found: %s\033[0m\n", args[0])
			}
			defer delete(full_path)
			pid := posix.fork()
			if pid == -1 {
				return "\033[31mFork failed.\033[0m"
			}
			if pid == 0 {
				posix.dup2(stdout_w, 1)
				posix.dup2(stderr_w, 2)
				posix.close(stdout_r)
				posix.close(stderr_r)
				c_argv := make([]cstring, len(args) + 1)
				for a, i in args {
					c_argv[i] = cstring(raw_data(a))
				}
				c_argv[len(args)] = nil
				c_full_path := cstring(raw_data(full_path))
				posix.execve(c_full_path, raw_data(c_argv), transmute([^]cstring) environ)
				delete(c_argv)
				posix._exit(1)
			} else {
				posix.close(stdout_w)
				posix.close(stderr_w)
				status: i32
				posix.waitpid(pid, &status, {})
				buf: [4096]u8
				output_sb := strings.builder_make()
				for {
					n := posix.read(stdout_r, raw_data(buf[:]), len(buf))
					if n <= 0 { break }
					strings.write_string(&output_sb, string(buf[:n]))
				}
				for {
					n := posix.read(stderr_r, raw_data(buf[:]), len(buf))
					if n <= 0 { break }
					strings.write_string(&output_sb, string(buf[:n]))
				}
				posix.close(stdout_r)
				posix.close(stderr_r)
				return strings.to_string(output_sb)
			}
		}

		find_full_path :: proc(cmd: string) -> string {
			if strings.contains(cmd, "/") {
				return strings.clone(cmd)
			}
			path_str := os.get_env("PATH")
			paths := strings.split(path_str, ":")
			defer delete(paths)
			for p in paths {
				fp := filepath.join({p, cmd})
				c_fp := cstring(raw_data(fp))
				if os.is_file(fp) && posix.access(c_fp, bit_set[posix.Mode_Flag_Bits; i32]{.R_OK, .X_OK}) == .OK {
					return fp
				}
				delete(fp)
			}
			return ""
		}

		WIFEXITED :: #force_inline proc "contextless" (status: i32) -> bool { return (status & 0x7f) == 0 }
		WEXITSTATUS :: #force_inline proc "contextless" (status: i32) -> i32 { return (status >> 8) & 0xff }

		parse_output :: proc(tool: string, raw: string, plugin_dir: string) -> string {
			plugin_file := filepath.join({plugin_dir, strings.concatenate({tool, ".lua"})})
			if !os.is_file(plugin_file) {
				return `{"error": "No plugin for tool"}`
			}
			L := luaL_newstate()
			if L == nil {
				return `{"error": "Failed to create Lua state"}`
			}
			defer lua_close(L)
			luaL_openlibs(L)
			if luaL_loadfilex(L, cstring(raw_data(plugin_file)), nil) != 0 || lua_pcallk(L, 0, 0, 0, 0, nil) != 0 {
				err := lua_tolstring(L, -1, nil)
				return fmt.tprintf(`{"error": "%s"}`, string(err))
			}
			_ = lua_getfield(L, LUA_GLOBALSINDEX, "parse")
			if lua_type(L, -1) != LUA_TFUNCTION {
				return `{"error": "No parse function in plugin"}`
			}
			lua_pushstring(L, cstring(raw_data(raw)))
			if lua_pcallk(L, 1, 1, 0, 0, nil) != 0 {
				err := lua_tolstring(L, -1, nil)
				return fmt.tprintf(`{"error": "%s"}`, string(err))
			}
			result := lua_tolstring(L, -1, nil)
			parsed_str := string(result)

			// Call workflow if exists
			_ = lua_getfield(L, LUA_GLOBALSINDEX, "workflow")
			if lua_type(L, -1) == LUA_TFUNCTION {
				lua_pushstring(L, cstring(raw_data(parsed_str)))
				if lua_pcallk(L, 1, 1, 0, 0, nil) == 0 {
					sugg := lua_tolstring(L, -1, nil)
					var data map[string]any
					json.unmarshal_string(parsed_str, &data)
					data["suggestions"] = string(sugg)
					new_json, _ := json.marshal(data)
					return string(new_json)
				}
			}

			return parsed_str
		}

		check_pre_attack :: proc(tool: string) {
			if tool == "aircrack-ng" {
				cmd_args := []string{"iwconfig"}
				exec_command(cmd_args)
				fmt.println("\033[33mChecklist: Ensure Wi-Fi card is in Monitor mode. Run 'airmon-ng start wlan0' if not.\033[0m")
			} else {
				fmt.println("\033[31mNo checklist for this tool.\033[0m")
			}
		}

		stealth_info :: proc() {
			uts: posix.utsname
			if posix.uname(&uts) != 0 {
				fmt.println("\033[31mFailed to get system info.\033[0m")
				return
			}
			hostname_len := 0
			for b in uts.nodename {
				if b == 0 { break }
				hostname_len += 1
			}
			hostname := string(uts.nodename[:hostname_len])
			fmt.printf("\033[32mHostname: %s\033[0m\n", hostname)
		}

		generate_report :: proc(date: string, log_dir: string, plugin_dir: string) {
			files, _ := os.read_dir(log_dir)
			sb := strings.builder_make()
			strings.write_string(&sb, "<html><body><h1>Pentest Report - ")
			strings.write_string(&sb, date)
			strings.write_string(&sb, "</h1>")
			for file in files {
				if strings.contains(file.name, date) {
					tool := strings.split(file.name, "_")[1]
					tool = strings.trim_suffix(tool, ".log")
					content, _ := os.read_entire_file(file.fullpath)
					parsed := parse_output(tool, string(content), plugin_dir)
					strings.write_string(&sb, fmt.tprintf("<h2>%s</h2><pre>%s</pre>", tool, parsed))
				}
			}
			strings.write_string(&sb, "</body></html>")
			report_file := "report.html"
			os.write_entire_file(report_file, transmute([]u8) strings.to_string(sb))
			fmt.printf("\033[32mReport generated: %s\033[0m\n", report_file)
		}

		detect_sandbox :: proc() {
			output := exec_command_with_output([]string{"cat", "/proc/cpuinfo"})
			if strings.contains(output, "hypervisor") {
				fmt.println("\033[33mDetected virtualization (possible sandbox).\033[0m")
			} else {
				fmt.println("\033[32mNo obvious sandbox detected.\033[0m")
			}
			// Add more checks
		}
