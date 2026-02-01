#+feature dynamic-literals
package main

import "core:fmt"
import "core:os"
import "core:strings"
import "core:path/filepath"
import "core:slice"
import "core:encoding/xml"
import "core:encoding/json"
import "core:sys/posix"
import "core:c"

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
    switch command {
    case "init":
        if len(args) < 1 {
            fmt.println("Usage: bph init <distro> (kali or blackarch)")
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
            fmt.println("Usage: bph enter <distro>")
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
            fmt.println("Usage: bph run <distro> <tool> [args...]")
            return
        }
        distro := args[0]
        if distro not_in distro_images {
            fmt.println("Unsupported distro.")
            return
        }
        tool_args := args[1:]
        cmd_args := make([]string, 4 + len(tool_args))
        cmd_args[0] = "distrobox"
        cmd_args[1] = "enter"
        cmd_args[2] = container_name(distro)
        cmd_args[3] = "--"
        copy(cmd_args[4:], tool_args)
        exec_command(cmd_args)
    case "docs":
        if len(args) < 1 {
            fmt.println("Usage: bph docs <tool>")
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
            fmt.println("Usage: bph parse <tool> <raw_output>")
            return
        }
        tool := args[0]
        raw_output := strings.join(args[1:], " ")
        parsed := parse_output(tool, raw_output)
        fmt.println(parsed)
    case "checklist":
        if len(args) < 1 {
            fmt.println("Usage: bph checklist <tool>")
            return
        }
        tool := args[0]
        check_pre_attack(tool)
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
    fmt.println("BPH (Be Pro Hacker) - Educational CLI for Pentesting Learning")
    fmt.println("Usage: bph <command> [args]")
    fmt.println("Commands:")
    fmt.println(" init <distro> Create container (distro: kali or blackarch)")
    fmt.println(" enter <distro> Enter container shell")
    fmt.println(" run <distro> <tool> [args] Run tool in container")
    fmt.println(" docs <tool> View tool documentation")
    fmt.println(" parse <tool> <raw_output> Parse tool output (e.g., nmap XML)")
    fmt.println(" checklist <tool> Run pre-attack checklist (e.g., for aircrack-ng)")
    fmt.println(" stealth Run stealth system info gatherer (educational)")
    fmt.println(" help Show this help")
    fmt.println("\nLearn ethically! Always get permission for testing.")
}

exec_command :: proc(args: []string) {
    if len(args) == 0 {
        return
    }
    // Find full path for args[0]
    full_path: string
    allocated := false
    defer if allocated { delete(full_path) }
    full_path = args[0]
    if !strings.contains(full_path, "/") {
        path_str := os.get_env("PATH")
        paths := strings.split(path_str, ":")
        defer delete(paths)
        found := false
        for p in paths {
            fp := filepath.join({p, args[0]})
            defer if !found { delete(fp) }
            if os.is_file(fp) {
                c_fp := cstring(raw_data(fp))
                if posix.access(c_fp, {posix.Mode_Flag_Bits.X_OK}) == .OK {
                    full_path = fp
                    allocated = true
                    found = true
                    // fp is now full_path, don't delete it here
                }
            }
            if found { break }
        }
        if !found {
            fmt.printf("Command not found: %s\n", args[0])
            return
        }
    }
    pid := posix.fork()
    if pid == -1 {
        fmt.println("Fork failed.")
        return
    }
    if pid == 0 {
        // Child process
        c_argv := make([]cstring, len(args) + 1)
        for a, i in args {
            c_argv[i] = cstring(raw_data(a))
        }
        c_argv[len(args)] = nil
        c_full_path := cstring(raw_data(full_path))
        // Exec
        _ = posix.execve(c_full_path, raw_data(c_argv), transmute([^]cstring) environ)
        // If we reach here, exec failed
        fmt.println("Exec failed.")
        delete(c_argv)
        posix._exit(1)
    } else {
        // Parent
        status: i32
        wpid := posix.waitpid(pid, &status, {})
        if wpid == -1 {
            fmt.println("Wait failed.")
        } else if WIFEXITED(status) && WEXITSTATUS(status) != 0 {
            fmt.printf("Command failed with status %d\n", WEXITSTATUS(status))
        }
    }
}

// Define wait macros if not present
WIFEXITED :: #force_inline proc "contextless" (status: i32) -> bool { return (status & 0x7f) == 0 }
WEXITSTATUS :: #force_inline proc "contextless" (status: i32) -> i32 { return (status >> 8) & 0xff }

// Parser: Extracts key info from raw output (example for nmap XML)
parse_output :: proc(tool: string, raw: string) -> string {
    if tool == "nmap" {
        doc, err := xml.parse_string(raw)
        if err != .None {
            return "Parse error"
        }
        defer xml.destroy(doc)
        // Extract hosts and ports (simplified)
        summary := strings.builder_make()
        for elem_idx in 0..<len(doc.elements) {
            elem := doc.elements[elem_idx]
            if elem.ident == "host" {
                addr := ""
                for attr in elem.attribs {
                    if attr.key == "addr" { addr = attr.val }
                }
                fmt.sbprintf(&summary, "Host: %s\n", addr)
                for v in elem.value {
                    switch id in v {
                    case u32:
                        child := doc.elements[id]
                        if child.ident == "ports" {
                            for pv in child.value {
                                switch pid in pv {
                                case u32:
                                    port_elem := doc.elements[pid]
                                    if port_elem.ident == "port" {
                                        portid := ""
                                        for attr in port_elem.attribs {
                                            if attr.key == "portid" { portid = attr.val }
                                        }
                                        state := ""
                                        service := ""
                                        for sv in port_elem.value {
                                            switch sid in sv {
                                            case u32:
                                                se := doc.elements[sid]
                                                if se.ident == "state" {
                                                    for attr in se.attribs {
                                                        if attr.key == "state" { state = attr.val }
                                                    }
                                                }
                                                if se.ident == "service" {
                                                    for attr in se.attribs {
                                                        if attr.key == "name" { service = attr.val }
                                                    }
                                                }
                                            case string:
                                                // ignore text
                                            }
                                        }
                                        if state == "open" {
                                            fmt.sbprintf(&summary, " Open Port: %s (%s)\n", portid, service)
                                        }
                                    }
                                case string:
                                    // ignore
                                }
                            }
                        }
                    case string:
                        // ignore
                    }
                }
            }
        }
        return strings.to_string(summary)
    }
    return "Unsupported tool for parsing"
}

// Pre-Attack Checklist: Checks network interfaces (e.g., monitor mode)
check_pre_attack :: proc(tool: string) {
    if tool == "aircrack-ng" {
        // Run 'iwconfig' or 'ip link' to check interfaces
        cmd_args := []string{"iwconfig"}
        exec_command(cmd_args)
        // Simulate parse: In real, parse output for "Mode:Monitor"
        fmt.println("Checklist: Ensure Wi-Fi card is in Monitor mode. Run 'airmon-ng start wlan0' if not.")
        // Add more checks, e.g., via reading /proc/net/dev
    } else {
        fmt.println("No checklist for this tool.")
    }
}

// Stealth Binary: Gather basic system info quietly
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
    // More: CPU info from /proc/cpuinfo, etc. Keep small.
    // Compile separately: odin build stealth.odin -out:stealth_info -no-bounds-check
}
