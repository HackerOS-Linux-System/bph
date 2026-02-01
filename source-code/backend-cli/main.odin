package main

import "core:fmt"
import "core:os"
import "core:strings"
import "core:slice"
import "core:encoding/xml"
import "core:encoding/json"

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

    container_name := proc(distro: string) -> string {
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
    fmt.println("  init <distro>     Create container (distro: kali or blackarch)")
    fmt.println("  enter <distro>    Enter container shell")
    fmt.println("  run <distro> <tool> [args]  Run tool in container")
    fmt.println("  docs <tool>       View tool documentation")
    fmt.println("  parse <tool> <raw_output>  Parse tool output (e.g., nmap XML)")
    fmt.println("  checklist <tool>  Run pre-attack checklist (e.g., for aircrack-ng)")
    fmt.println("  stealth           Run stealth system info gatherer (educational)")
    fmt.println("  help              Show this help")
    fmt.println("\nLearn ethically! Always get permission for testing.")
}

exec_command :: proc(args: []string) {
    pid := os.fork()
    if pid == 0 {
        os.execvp(args[0], args)
        fmt.println("Exec failed.")
        os.exit(1)
    } else if pid > 0 {
        _, status := os.waitpid(pid, 0)
        if status != 0 {
            fmt.printf("Command failed with status %d\n", status)
        }
    } else {
        fmt.println("Fork failed.")
    }
}

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
        for elem in doc.elements {
            if elem.ident == "host" {
                addr := ""
                for attr in elem.attribs {
                    if attr.key == "addr" { addr = attr.val }
                }
                fmt.sbprintf(&summary, "Host: %s\n", addr)
                for child in elem.value.(xml.Element).elements {
                    if child.ident == "ports" {
                        for port_elem in child.elements {
                            if port_elem.ident == "port" {
                                portid := ""
                                state := ""
                                service := ""
                                for attr in port_elem.attribs {
                                    if attr.key == "portid" { portid = attr.val }
                                }
                                for state_elem in port_elem.elements {
                                    if state_elem.ident == "state" {
                                        for attr in state_elem.attribs {
                                            if attr.key == "state" { state = attr.val }
                                        }
                                    }
                                    if state_elem.ident == "service" {
                                        for attr in state_elem.attribs {
                                            if attr.key == "name" { service = attr.val }
                                        }
                                    }
                                }
                                if state == "open" {
                                    fmt.sbprintf(&summary, "  Open Port: %s (%s)\n", portid, service)
                                }
                            }
                        }
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
        pid := os.fork()
        if pid == 0 {
            os.execvp("iwconfig", cmd_args)
            os.exit(1)
        }
        _, _ = os.waitpid(pid, 0)

        // Simulate parse: In real, parse output for "Mode:Monitor"
        fmt.println("Checklist: Ensure Wi-Fi card is in Monitor mode. Run 'airmon-ng start wlan0' if not.")
        // Add more checks, e.g., via reading /proc/net/dev
    } else {
        fmt.println("No checklist for this tool.")
    }
}

// Stealth Binary: Gather basic system info quietly
stealth_info :: proc() {
    hostname, _ := os.get_host_name()
    // Get IP: Simplified, in real use socket or exec 'ip addr'
    fmt.printf("Hostname: %s\n", hostname)
    // More: CPU info from /proc/cpuinfo, etc. Keep small.
    // Compile separately: odin build stealth.odin -out:stealth_info -no-bounds-check
}
