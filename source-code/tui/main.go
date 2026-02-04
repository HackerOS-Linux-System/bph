// bph-tui
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/progress"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	"github.com/charmbracelet/lipgloss"
)

type toolDoc struct {
	name    string
	desc    string
	example string
}

type scenario struct {
	name  string
	steps []string
}

var (
	distroImages = map[string]string{
		"kali":      "docker.io/kalilinux/kali-rolling:latest",
		"blackarch": "docker.io/blackarch/blackarch:latest",
	}
	dvwaImage    = "vulner/web-dvwa:latest"
	toolDocs     = []toolDoc{
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
	scenarios = []scenario{
		{"Scan Local Network", []string{"Check interfaces (backend checklist nmap)", "Run nmap on 192.168.1.0/24", "Parse results (backend parse nmap <output>)", "Ethics: Only on your network!"}},
     {"Wi-Fi Assessment", []string{"Enable monitor mode (backend checklist aircrack-ng)", "Run airodump-ng", "Analyze captures"}},
     {"Web Vuln Scan", []string{"Start DVWA", "Run nikto -h http://localhost:8080", "Run sqlmap -u http://localhost:8080/vulnerabilities/sqli/?id=1&Submit=Submit", "Review findings"}},
	}
	style = lipgloss.NewStyle().
	BorderStyle(lipgloss.NormalBorder()).
	BorderForeground(lipgloss.Color("240"))
	statusStyle = lipgloss.NewStyle().
	Foreground(lipgloss.Color("205")).
	BorderStyle(lipgloss.NormalBorder()).
	BorderBottom(true).
	BorderForeground(lipgloss.Color("240"))
	warnTools = []string{"hydra", "sqlmap", "nikto"}
	quizzes   = map[string]struct {
		q string
		a string
	}{
		"nmap":        {"What does -sV do in nmap?", "version detection"},
		"aircrack-ng": {"What does airodump-ng do?", "capture packets"},
		"nikto":       {"What does Nikto scan for?", "web vulnerabilities"},
		"sqlmap":      {"What vulnerability does sqlmap exploit?", "sql injection"},
	}
	backendPath string
)

func init() {
	home, _ := os.UserHomeDir()
	backendPath = filepath.Join(home, ".hackeros", "bph", "backend")
}

type model struct {
	distro           string
	actionList       list.Model
	toolList         list.Model
	scenarioList     list.Model
	viewport         viewport.Model
	progress         progress.Model
	textinput        textinput.Model
	state            string // "select_distro", "main", "select_tool", "view_doc", "run_tool", "guided_lab", "progress", "confirm_warning", "input_snapshot_file", "view_output"
	substate         string // for snapshot: "save", "restore"
	selectedTool     string
	selectedLab      int
	currentStep      int
	output           string
	status           string
	labStatus        string
	quitting         bool
}

type statusTickMsg time.Time
type progressTickMsg struct{}
type animationMsg progress.FrameMsg
type checkTickMsg time.Time

func initialModel() model {
	actionItems := []list.Item{
		item{title: "Init Container", desc: "Create a new container"},
		item{title: "Enter Container", desc: "Enter the container shell"},
		item{title: "Run Tool", desc: "Run a pentesting tool"},
		item{title: "View Docs", desc: "View tool documentation"},
		item{title: "Guided Labs", desc: "Interactive learning scenarios"},
		item{title: "Start Offline Lab", desc: "Start DVWA for offline practice"},
		item{title: "Snapshot Save", desc: "Save container snapshot"},
		item{title: "Snapshot Restore", desc: "Restore container snapshot"},
		item{title: "Help", desc: "Show help"},
		item{title: "Quit", desc: "Exit the TUI"},
	}
	actionList := list.New(actionItems, list.NewDefaultDelegate(), 0, 0)
	actionList.Title = "BPH Actions - Select Distro First"
	toolItems := make([]list.Item, len(toolDocs))
	for i, t := range toolDocs {
		toolItems[i] = item{title: t.name, desc: t.desc}
	}
	toolList := list.New(toolItems, list.NewDefaultDelegate(), 0, 0)
	toolList.Title = "Select Tool"
	scenarioItems := make([]list.Item, len(scenarios))
	for i, s := range scenarios {
		scenarioItems[i] = item{title: s.name, desc: "Guided pentesting lab"}
	}
	scenarioList := list.New(scenarioItems, list.NewDefaultDelegate(), 0, 0)
	scenarioList.Title = "Select Guided Lab"
	vp := viewport.New(0, 0)
	vp.Style = style
	prog := progress.New(progress.WithDefaultGradient())
	ti := textinput.New()
	ti.Prompt = "> "
	ti.Focus()
	return model{
		actionList:   actionList,
		toolList:     toolList,
		scenarioList: scenarioList,
		viewport:     vp,
		progress:     prog,
		textinput:    ti,
		state:        "select_distro",
		status:       "Loading status...",
	}
}

func (m model) Init() tea.Cmd {
	return tea.Batch(statusTickCmd(), textinput.Blink)
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd
	switch msg := msg.(type) {
		case tea.KeyMsg:
			switch msg.String() {
				case "ctrl+c", "q":
					m.quitting = true
					return m, tea.Quit
				case "enter":
					switch m.state {
						case "select_distro":
							if m.distro == "kali" {
								m.distro = "blackarch"
							} else {
								m.distro = "kali"
							}
							m.actionList.Title = fmt.Sprintf("BPH Actions (%s)", m.distro)
							m.state = "main"
						case "main":
							selected := m.actionList.SelectedItem().(item).title
							switch selected {
								case "Init Container":
									m.state = "progress"
									m.progress.SetPercent(0)
									cmds = append(cmds, m.initContainer(), animationTickCmd())
								case "Enter Container":
									m.output = execBackend([]string{"enter", m.distro})
								case "Run Tool":
									m.state = "select_tool"
									m.toolList.Title = "Select Tool to Run"
								case "View Docs":
									m.state = "select_tool"
									m.toolList.Title = "Select Tool for Docs"
								case "Guided Labs":
									m.state = "guided_lab"
									m.selectedLab = -1
									m.currentStep = -1
									m.labStatus = ""
								case "Start Offline Lab":
									execPodman([]string{"pull", dvwaImage})
									output := execPodman([]string{"run", "-d", "-p", "8080:80", "--name", "bph-dvwa", dvwaImage})
									m.output = fmt.Sprintf("DVWA started: %s\nAccess at http://localhost:8080", output)
								case "Snapshot Save":
									m.state = "input_snapshot_file"
									m.substate = "save"
									m.textinput.SetValue("")
									m.textinput.Placeholder = "Enter file path for snapshot"
								case "Snapshot Restore":
									m.state = "input_snapshot_file"
									m.substate = "restore"
									m.textinput.SetValue("")
									m.textinput.Placeholder = "Enter file path for snapshot"
								case "Help":
									m.output = helpText()
									m.viewport.SetContent(m.output)
								case "Quit":
									m.quitting = true
									return m, tea.Quit
							}
								case "select_tool":
									m.selectedTool = m.toolList.SelectedItem().(item).title
									if strings.Contains(m.toolList.Title, "Run") {
										if slice.contains(warnTools, m.selectedTool) {
											m.state = "confirm_warning"
										} else {
											m.runTool()
										}
									} else {
										for _, t := range toolDocs {
											if t.name == m.selectedTool {
												m.output = fmt.Sprintf("%s: %s\nExample: %s", t.name, t.desc, t.example)
												m.viewport.SetContent(m.output)
												break
											}
										}
										m.state = "main"
									}
								case "confirm_warning":
									if msg.String() == "y" {
										m.runTool()
									} else {
										m.state = "main"
									}
								case "guided_lab":
									if m.selectedLab == -1 {
										m.selectedLab = m.scenarioList.Index()
										m.currentStep = -1
										m.advanceLabStep()
										cmds = append(cmds, checkTickCmd())
									} else if m.currentStep >= 0 && strings.Contains(m.labStatus, "complete") {
										m.advanceLabStep()
										cmds = append(cmds, checkTickCmd())
									}
								case "quiz":
									answer := strings.ToLower(m.textinput.Value())
									correct := strings.ToLower(quizzes[m.selectedTool].a)
									if strings.Contains(answer, correct) {
										m.labStatus = "Quiz correct! Proceeding."
										m.advanceLabStep()
									} else {
										m.labStatus = "Incorrect. Try again."
									}
									m.textinput.SetValue("")
									m.state = "guided_lab"
								case "input_snapshot_file":
									file := m.textinput.Value()
									if file == "" {
										m.output = "File path required."
									} else {
										var args []string
										if m.substate == "save" {
											args = []string{"snapshot", "save", m.distro, file}
										} else {
											args = []string{"snapshot", "restore", m.distro, file}
										}
										m.output = execBackend(args)
									}
									m.state = "main"
					}
					return m, tea.Batch(cmds...)
								case "y", "n":
									if m.state == "confirm_warning" {
										if msg.String() == "y" {
											m.runTool()
										} else {
											m.state = "main"
										}
									}
			}
								case tea.WindowSizeMsg:
									h, v := style.GetFrameSize()
									m.actionList.SetSize(msg.Width-h, msg.Height-v-5)
									m.toolList.SetSize(msg.Width-h, msg.Height-v-5)
									m.scenarioList.SetSize(msg.Width-h, msg.Height-v-5)
									m.viewport.Width = msg.Width - h
									m.viewport.Height = msg.Height - v - 5
									m.progress.Width = msg.Width - h
								case statusTickMsg:
									m.status = getContainerStatus(m.distro)
									cmds = append(cmds, statusTickCmd())
								case progressTickMsg:
									perc := m.progress.Percent()
									if perc >= 1.0 {
										output := execDistrobox([]string{"create", "--name", containerName(m.distro), "--image", distroImages[m.distro]})
										m.output = output
										m.state = "main"
										return m, nil
									}
									_ = m.progress.SetPercent(perc + 0.1)
									cmds = append(cmds, progressTickCmd())
								case animationMsg:
									if m.state != "progress" {
										return m, nil
									}
									pm, cmd := m.progress.Update(msg)
									if p, ok := pm.(progress.Model); ok {
										m.progress = p
									}
									cmds = append(cmds, cmd, animationTickCmd())
								case checkTickMsg:
									if m.state == "guided_lab" && m.currentStep >= 0 {
										m.checkLabProgress()
										cmds = append(cmds, checkTickCmd())
									}
	}
	var cmd tea.Cmd
	switch m.state {
		case "main":
			m.actionList, cmd = m.actionList.Update(msg)
		case "select_tool":
			m.toolList, cmd = m.toolList.Update(msg)
		case "guided_lab":
			m.scenarioList, cmd = m.scenarioList.Update(msg)
		case "view_doc", "view_output":
			m.viewport, cmd = m.viewport.Update(msg)
		case "quiz", "input_snapshot_file":
			m.textinput, cmd = m.textinput.Update(msg)
	}
	cmds = append(cmds, cmd)
	return m, tea.Batch(cmds...)
}

func (m *model) runTool() {
	rawOutput := execBackend([]string{"run", m.distro, m.selectedTool}) // Add real args later
	home, _ := os.UserHomeDir()
	logDir := filepath.Join(home, ".hackeros", "bph", "logs")
	os.MkdirAll(logDir, 0755)
	date := time.Now().Format("2006-01-02")
	logFile := filepath.Join(logDir, date+"_"+m.selectedTool+".log")
	os.WriteFile(logFile, []byte(rawOutput), 0644)
	parsed := execBackend([]string{"parse", m.selectedTool, rawOutput})
	var data map[string]interface{}
	err := json.Unmarshal([]byte(parsed), &data)
	if err != nil {
		m.output = parsed
	} else {
		m.output = m.formatParsedOutput(data)
	}
	m.viewport.SetContent(m.output)
	m.state = "view_output"
}

func (m model) formatParsedOutput(data map[string]interface{}) string {
	typ, ok := data["type"].(string)
	if !ok {
		return "Invalid parsed data"
	}
	switch typ {
		case "nmap":
			hosts, _ := data["hosts"].([]interface{})
			gateway := m.getDefaultGateway()
			sb := strings.Builder{}
			fmt.Fprintf(&sb, "[Gateway %s]\n", gateway)
			for _, h := range hosts {
				hmap := h.(map[string]interface{})
				addr := hmap["addr"].(string)
				if addr == gateway {
					continue
				}
				ports, _ := hmap["ports"].([]interface{})
				portStrs := []string{}
				for _, p := range ports {
					pmap := p.(map[string]interface{})
					if pmap["state"] == "open" {
						portStrs = append(portStrs, pmap["portid"].(string))
					}
				}
				portsStr := strings.Join(portStrs, ", ")
				if portsStr == "" {
					portsStr = "brak"
				}
				fmt.Fprintf(&sb, "├── [%s] (Ports: %s)\n", addr, portsStr)
			}
			return sb.String()
		case "nikto":
			vulns, _ := data["vulns"].([]interface{})
			sb := strings.Builder{}
			fmt.Fprintln(&sb, "Vulnerabilities:")
			for _, v := range vulns {
				vmap := v.(map[string]interface{})
				fmt.Fprintf(&sb, "OSVDB-%s: %s\n", vmap["id"], vmap["desc"])
			}
			return sb.String()
		case "sqlmap":
			dbs, _ := data["databases"].([]interface{})
			tables, _ := data["tables"].(map[string]interface{})
			sb := strings.Builder{}
			fmt.Fprintln(&sb, "Databases:")
			for _, db := range dbs {
				fmt.Fprintln(&sb, db.(string))
			}
			for db, tbls := range tables {
				fmt.Fprintf(&sb, "Tables in %s:\n", db)
				for _, t := range tbls.([]interface{}) {
					fmt.Fprintln(&sb, t.(string))
				}
			}
			return sb.String()
		case "aircrack":
			nets, _ := data["networks"].([]interface{})
			sb := strings.Builder{}
			fmt.Fprintln(&sb, "BSSID\tESSID\tPower")
			for _, n := range nets {
				nmap := n.(map[string]interface{})
				fmt.Fprintf(&sb, "%s\t%s\t%s\n", nmap["bssid"], nmap["essid"], nmap["power"])
			}
			return sb.String()
	}
	return "Unsupported format"
}

func (m model) getDefaultGateway() string {
	cmd := exec.Command("ip", "route", "show", "default")
	output, _ := cmd.Output()
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "default via") {
			fields := strings.Fields(line)
			return fields[2]
		}
	}
	return "Unknown"
}

func (m *model) advanceLabStep() {
	m.currentStep++
	if m.currentStep < len(scenarios[m.selectedLab].steps) {
		step := scenarios[m.selectedLab].steps[m.currentStep]
		m.output = fmt.Sprintf("Lab: %s\nStep %d: %s", scenarios[m.selectedLab].name, m.currentStep+1, step)
		if strings.Contains(step, "backend checklist") {
			tool := strings.Split(step, " ")[2]
			m.output += "\n" + execBackend([]string{"checklist", tool})
		}
		// Check if quiz needed
		for tool := range quizzes {
			if strings.Contains(strings.ToLower(step), tool) {
				m.selectedTool = tool
				m.state = "quiz"
				m.textinput.Placeholder = quizzes[tool].q
				m.labStatus = quizzes[tool].q
				return
			}
		}
		m.labStatus = "Perform the step..."
	} else {
		m.output += "\nLab Complete! Review ethics."
		m.state = "main"
	}
	m.viewport.SetContent(m.output + "\n" + m.labStatus)
}

func (m *model) checkLabProgress() {
	home, _ := os.UserHomeDir()
	logDir := filepath.Join(home, ".hackeros", "bph", "logs")
	switch {
		case m.selectedLab == 0 && m.currentStep == 1: // Scan Local Network, Run nmap
			files, _ := filepath.Glob(filepath.Join(logDir, "*_nmap.log"))
			complete := false
			for _, f := range files {
				content, _ := os.ReadFile(f)
				if strings.Contains(string(content), "192.168.1.") {
					complete = true
					break
				}
			}
			if complete {
				m.labStatus = "Nmap scan detected - step complete!"
			} else {
				m.labStatus = "Run nmap on 192.168.1.0/24 and log results."
			}
		case m.selectedLab == 1 && m.currentStep == 0: // Wi-Fi Assessment, Enable monitor mode
			cmd := exec.Command("ip", "link", "show", "dev", "wlan0mon")
			if cmd.Run() == nil {
				m.labStatus = "Monitor mode enabled - step complete!"
			} else {
				m.labStatus = "Monitor mode not enabled yet."
			}
		case m.selectedLab == 2 && m.currentStep == 2: // Web Vuln Scan, Run sqlmap
			// Check inside container for dump files
			checkCmd := execDistrobox([]string{"enter", containerName(m.distro), "--", "ls", "/root/sqlmap/output"})
			if strings.Contains(checkCmd, ".csv") || strings.Contains(checkCmd, ".txt") {
				m.labStatus = "SQL dump detected - step complete!"
			} else {
				m.labStatus = "Run sqlmap and dump data."
			}
	}
	m.viewport.SetContent(m.output + "\n" + m.labStatus)
}

func (m model) View() string {
	if m.quitting {
		return "Goodbye! Learn ethically.\n"
	}
	statusPanel := statusStyle.Render(m.status)
	base := ""
	switch m.state {
		case "select_distro":
			base = "Press Enter to toggle distro: " + m.distro
		case "main":
			base = m.actionList.View()
		case "select_tool":
			base = m.toolList.View()
		case "guided_lab":
			base = m.scenarioList.View() + "\n" + m.viewport.View()
		case "view_doc", "view_output":
			base = m.viewport.View()
		case "progress":
			base = m.progress.View() + "\nInitializing container..."
		case "confirm_warning":
			base = "Warning: Do you have written permission to test this target? (y/n)"
		case "quiz":
			base = m.labStatus + "\n" + m.textinput.View()
		case "input_snapshot_file":
			base = m.textinput.Placeholder + "\n" + m.textinput.View()
	}
	return statusPanel + "\n" + style.Render(base) + "\n\nOutput:\n" + m.output
}

func containerName(distro string) string {
	return "bph-" + distro
}

func execDistrobox(args []string) string {
	fullArgs := append([]string{"distrobox"}, args...)
	cmd := exec.Command(fullArgs[0], fullArgs[1:]...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Sprintf("Error: %v\n%s", err, output)
	}
	return string(output)
}

func execPodman(args []string) string {
	cmd := exec.Command("podman", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Sprintf("Error: %v\n%s", err, output)
	}
	return string(output)
}

func execBackend(args []string) string {
	cmd := exec.Command(backendPath, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Sprintf("Backend error: %v\n%s", err, output)
	}
	return string(output)
}

func getContainerStatus(distro string) string {
	cmd := exec.Command("podman", "stats", "--no-stream", containerName(distro))
	output, _ := cmd.CombinedOutput()
	if strings.Contains(string(output), "No such container") {
		return fmt.Sprintf("Container %s: Stopped", distro)
	}
	lines := strings.Split(string(output), "\n")
	if len(lines) > 1 {
		fields := strings.Fields(lines[1])
		if len(fields) > 3 {
			return fmt.Sprintf("Container %s: Running | CPU: %s | Mem: %s", distro, fields[1], fields[3])
		}
	}
	return fmt.Sprintf("Container %s: Unknown", distro)
}

func statusTickCmd() tea.Cmd {
	return tea.Tick(5*time.Second, func(t time.Time) tea.Msg {
		return statusTickMsg(t)
	})
}

func progressTickCmd() tea.Cmd {
	return tea.Tick(200*time.Millisecond, func(_ time.Time) tea.Msg {
		return progressTickMsg{}
	})
}

func animationTickCmd() tea.Cmd {
	return tea.Tick(50*time.Millisecond, func(_ time.Time) tea.Msg {
		return animationMsg(progress.FrameMsg{})
	})
}

func checkTickCmd() tea.Cmd {
	return tea.Tick(2*time.Second, func(t time.Time) tea.Msg {
		return checkTickMsg(t)
	})
}

func (m *model) initContainer() tea.Cmd {
	return progressTickCmd()
}

func helpText() string {
	return `BPH TUI - Educational for Pentesting
	Select actions with arrows, enter to confirm.
	Distro: kali or blackarch.
	Guided Labs: Step-by-step learning with validation and quizzes.
	Offline Lab: Practice on local DVWA.
	Snapshots: Save/restore container state.
	Learn safely!`
}

type item struct {
	title, desc string
}

func (i item) Title() string       { return i.title }
func (i item) Description() string { return i.desc }
func (i item) FilterValue() string { return i.title }

func main() {
	home, _ := os.UserHomeDir()
	logDir := filepath.Join(home, ".hackeros", "bph")
	os.MkdirAll(logDir, 0755)
	p := tea.NewProgram(initialModel(), tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Println("Error running program:", err)
		os.Exit(1)
	}
}
