#feature dynamic-literals
package main

import "core:fmt"
import "core:os"
import "core:strings"
import "core:path/filepath"
import "core:slice"
import "core:encoding/xml"
import "core:encoding/json"
import "core:time"
import "core:bufio"
import "core:io"
import "core:sys/posix"
import "core:c"

foreign import lua_lib "system:lua5.4"

LUA_TFUNCTION :: 6 // From lua.h

luaL_newstate :: proc "c" () -> rawptr

luaL_openlibs :: proc "c" (L: rawptr)

luaL_loadfile :: proc "c" (L: rawptr, filename: cstring) -> c.int

lua_pcall :: proc "c" (L: rawptr, nargs, nresults, errfunc: c.int) -> c.int

lua_getglobal :: proc "c" (L: rawptr, name: cstring) -> c.int

lua_pushstring :: proc "c" (L: rawptr, s: cstring)

lua_tostring :: proc "c" (L: rawptr, idx: c.int) -> cstring

lua_close :: proc "c" (L: rawptr)

lua_type :: proc "c" (L: rawptr, idx: c.int) -> c.int

foreign import system_lib "system:c"

foreign system_lib {
    environ: ^^c.char
}

ToolDoc :: struct {
    name: string,
    desc: string,
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
        "kali" = "docker.io/kalilinux/kali-rolling:latest",
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
    }
    container_name :: proc(distro: string) -> string {
        return strings.concatenate({"bph-", distro})
    }
    home := os.get_env("HOME")
    log_dir := filepath.join({home, ".hackeros", "bph", "logs"})
    plugin_dir := filepath.join({home, ".hackeros", "bph", "plugins"})
    os.make_directory(log_dir, 0755)
    os.make_directory(plugin_dir, 0755)
    warn_tools := []string{"hydra", "sqlmap", "nikto"}
    switch command {
    case "init":
        if len(args) < 1 {
            fmt.println("Usage: backend init <distro> (kali or blackarch)")
            return
        }
        distro := args[0]
        if distro not_in distro_images {
            fmt.println("Unsupported distro. Use kali or blackarch.")
            return
        }
        image := distro_images[distro]
        cmd_args := []string{"distrobox", "create", "--name", container_name(distro), "--image", image}
        exec_command(cmd_args)
    case "enter":
        if len(args) < 1 {
            fmt.println("Usage: backend enter <distro>")
            return
        }
        distro := args[0]
        if distro not_in distro_images {
            fmt.println("Unsupported distro.")
            return
        }
        cmd_args := []string{"distrobox", "enter", container_name(distro)}
        exec_command(cmd_args)
    case "run":
        if len(args) < 2 {
            fmt.println("Usage: backend run <distro> <tool> [args...]")
            return
        }
        distro := args[0]
        if distro not_in distro_images {
            fmt.println("Unsupported distro.")
            return
        }
        tool := args[1]
        tool_args := args[1:]
        if slice.contains(warn_tools, tool) {
            fmt.println("Warning: Do you have written permission to test this target? (y/n)")
            reader: bufio.Reader
            bufio.reader_init(&reader, os.stream_from_handle(os.stdin))
            defer bufio.reader_destroy(&reader)
            byte, _ := bufio.reader_read_byte(&reader)
            if byte != 'y' && byte != 'Y' {
                fmt.println("Aborting.")
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
        year, month, day, _ := time.time_to_parts(t)
        date_str := fmt.tprintf("%d-%02d-%02d", year, int(month), day)
        log_file := strings.concatenate({date_str, "_", tool, ".log"})
        full_log := filepath.join({log_dir, log_file})
        os.write_entire_file(full_log, transmute([]u8) output)
        fmt.print(output)
    case "docs":
        if len(args) < 1 {
            fmt.println("Usage: backend docs <tool>")
            return
        }
        tool_name := args[0]
        for tool in tool_docs {
            if tool.name == tool_name {
                fmt.printf("%s: %s\nExample: %s\n", tool.name, tool.desc, tool.example)
                return
            }
        }
        fmt.println("Tool not found. Available: nmap, metasploit, wireshark, aircrack-ng, burpsuite, john, hydra, nikto, sqlmap, maltego")
    case "parse":
        if len(args) < 2 {
            fmt.println("Usage: backend parse <tool> <raw_output>")
            return
        }
        tool := args[0]
        raw_output := strings.join(args[1:], " ")
        parsed := parse_output(tool, raw_output, plugin_dir)
        fmt.println(parsed)
    case "checklist":
        if len(args) < 1 {
            fmt.println("Usage: backend checklist <tool>")
            return
        }
        tool := args[0]
        check_pre_attack(tool)
    case "snapshot":
        if len(args) < 3 {
            fmt.println("Usage: backend snapshot save/restore <distro> <file>")
            return
        }
        mode := args[0]
        distro := args[1]
        file := args[2]
        if distro not_in distro_images {
            fmt.println("Unsupported distro.")
            return
        }
        cmd_args: []string
        if mode == "save" {
            cmd_args = []string{"podman", "container", "checkpoint", "--export", file, container_name(distro)}
        } else if mode == "restore" {
            cmd_args = []string{"podman", "container", "restore", "--import", file, container_name(distro)}
        } else {
            fmt.println("Invalid mode: save or restore")
            return
        }
        exec_command(cmd_args)
    case "stealth":
        stealth_info()
    case "help":
        print_help()
    case:
        fmt.println("Unknown command.")
        print_help()
    }
}

print_help :: proc() {
    fmt.println("Backend for BPH - Educational CLI for Pentesting Learning")
    fmt.println("Usage: backend <command> [args]")
    fmt.println("Commands:")
    fmt.println(" init <distro> Create container (distro: kali or blackarch)")
    fmt.println(" enter <distro> Enter container shell")
    fmt.println(" run <distro> <tool> [args] Run tool in container with logging")
    fmt.println(" docs <tool> View tool documentation")
    fmt.println(" parse <tool> <raw_output> Parse tool output to JSON")
    fmt.println(" checklist <tool> Run pre-attack checklist")
    fmt.println(" snapshot save/restore <distro> <file> Snapshot container")
    fmt.println(" stealth Run stealth system info gatherer (educational)")
    fmt.println(" help Show this help")
    fmt.println("\nLearn ethically! Always get permission for testing.")
}

exec_command :: proc(args: []string) {
    if len(args) == 0 {
        return
    }
    full_path := find_full_path(args[0])
    if full_path == "" {
        fmt.printf("Command not found: %s\n", args[0])
        return
    }
    defer delete(full_path)
    pid := posix.fork()
    if pid == -1 {
        fmt.println("Fork failed.")
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
        fmt.println("Exec failed.")
        delete(c_argv)
        posix._exit(1)
    } else {
        status: i32
        posix.waitpid(pid, &status, {})
        if WIFEXITED(status) && WEXITSTATUS(status) != 0 {
            fmt.printf("Command failed with status %d\n", WEXITSTATUS(status))
        }
    }
}

exec_command_with_output :: proc(args: []string) -> string {
    stdout_fds: [2]posix.FD
    if posix.pipe(&stdout_fds) != 0 {
        return "Pipe failed."
    }
    stdout_r := stdout_fds[0]
    stdout_w := stdout_fds[1]
    stderr_fds: [2]posix.FD
    if posix.pipe(&stderr_fds) != 0 {
        return "Pipe failed."
    }
    stderr_r := stderr_fds[0]
    stderr_w := stderr_fds[1]
    full_path := find_full_path(args[0])
    if full_path == "" {
        return fmt.tprintf("Command not found: %s\n", args[0])
    }
    defer delete(full_path)
    pid := posix.fork()
    if pid == -1 {
        return "Fork failed."
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
            strings.builder_write(&output_sb, buf[:n])
        }
        for {
            n := posix.read(stderr_r, raw_data(buf[:]), len(buf))
            if n <= 0 { break }
            strings.builder_write(&output_sb, buf[:n])
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
        if os.is_file(fp) && posix.access(c_fp, {posix.R_OK, posix.X_OK}) == 0 {
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
    if luaL_loadfile(L, cstring(raw_data(plugin_file))) != 0 || lua_pcall(L, 0, 0, 0) != 0 {
        err := lua_tostring(L, -1)
        return fmt.tprintf(`{"error": "%s"}`, string(err))
    }
    _ = lua_getglobal(L, "parse")
    if lua_type(L, -1) != LUA_TFUNCTION {
        return `{"error": "No parse function in plugin"}`
    }
    lua_pushstring(L, cstring(raw_data(raw)))
    if lua_pcall(L, 1, 1, 0) != 0 {
        err := lua_tostring(L, -1)
        return fmt.tprintf(`{"error": "%s"}`, string(err))
    }
    result := lua_tostring(L, -1)
    return string(result)
}

check_pre_attack :: proc(tool: string) {
    if tool == "aircrack-ng" {
        cmd_args := []string{"iwconfig"}
        exec_command(cmd_args)
        fmt.println("Checklist: Ensure Wi-Fi card is in Monitor mode. Run 'airmon-ng start wlan0' if not.")
    } else {
        fmt.println("No checklist for this tool.")
    }
}

stealth_info :: proc() {
    uts: posix.utsname
    if posix.uname(&uts) != 0 {
        fmt.println("Failed to get system info.")
        return
    }
    hostname_len := 0
    for b in uts.nodename {
        if b == 0 { break }
        hostname_len += 1
    }
    hostname := string(uts.nodename[:hostname_len])
    fmt.printf("Hostname: %s\n", hostname)
}
