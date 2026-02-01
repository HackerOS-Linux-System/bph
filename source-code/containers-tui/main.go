package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/progress"
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
	toolDocs = []toolDoc{
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
		{"Scan Local Network", []string{"Check interfaces (bph checklist nmap)", "Run nmap on 192.168.1.0/24", "Parse results (bph parse nmap <output>)", "Ethics: Only on your network!"}},
		{"Wi-Fi Assessment", []string{"Enable monitor mode (bph checklist aircrack-ng)", "Run airodump-ng", "Analyze captures"}},
	}
	style = lipgloss.NewStyle().
		BorderStyle(lipgloss.NormalBorder()).
		BorderForeground(lipgloss.Color("240"))
	statusStyle = lipgloss.NewStyle().
		Foreground(lipgloss.Color("205")).
		BorderStyle(lipgloss.NormalBorder()).
		BorderBottom(true).
		BorderForeground(lipgloss.Color("240"))
)

type model struct {
	distro       string
	actionList   list.Model
	toolList     list.Model
	scenarioList list.Model
	viewport     viewport.Model
	progress     progress.Model
	state        string // "select_distro", "main", "select_tool", "view_doc", "run_tool", "guided_lab", "progress"
	selectedTool string
	selectedLab  int
	currentStep  int
	output       string
	status       string
	quitting     bool
}

type statusTickMsg time.Time

func initialModel() model {
	actionItems := []list.Item{
		item{title: "Init Container", desc: "Create a new container"},
		item{title: "Enter Container", desc: "Enter the container shell"},
		item{title: "Run Tool", desc: "Run a pentesting tool"},
		item{title: "View Docs", desc: "View tool documentation"},
		item{title: "Guided Labs", desc: "Interactive learning scenarios"},
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

	return model{
		actionList:   actionList,
		toolList:     toolList,
		scenarioList: scenarioList,
		viewport:     vp,
		progress:     prog,
		state:        "select_distro",
		status:       "Loading status...",
	}
}

func (m model) Init() tea.Cmd {
	return tea.Batch(statusTickCmd(), m.progress.Animate())
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
					cmds = append(cmds, m.initContainer())
				case "Enter Container":
					m.output = execDistrobox([]string{"enter", containerName(m.distro)})
				case "Run Tool":
					m.state = "select_tool"
					m.toolList.Title = "Select Tool to Run"
				case "View Docs":
					m.state = "select_tool"
					m.toolList.Title = "Select Tool for Docs"
				case "Guided Labs":
					m.state = "guided_lab"
					m.currentStep = 0
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
					// Run and parse via Odin backend
					rawOutput := execDistrobox([]string{"enter", containerName(m.distro), "--", m.selectedTool}) // Simplified, add args
					m.output = execBph([]string{"parse", m.selectedTool, rawOutput})
				} else {
					for _, t := range toolDocs {
						if t.name == m.selectedTool {
							m.output = fmt.Sprintf("%s: %s\nExample: %s", t.name, t.desc, t.example)
							m.viewport.SetContent(m.output)
							break
						}
					}
				}
				m.state = "main"
			case "guided_lab":
				if m.selectedLab == 0 { // Select lab first
					m.selectedLab = m.scenarioList.Cursor()
					m.output = fmt.Sprintf("Starting Lab: %s\nStep 1: %s", scenarios[m.selectedLab].name, scenarios[m.selectedLab].steps[0])
					// Integrate checklist
					if strings.Contains(m.output, "checklist") {
						m.output += "\n" + execBph([]string{"checklist", "nmap"}) // Example
					}
				} else {
					m.currentStep++
					if m.currentStep < len(scenarios[m.selectedLab].steps) {
						m.output += fmt.Sprintf("\nStep %d: %s", m.currentStep+1, scenarios[m.selectedLab].steps[m.currentStep])
					} else {
						m.output += "\nLab Complete! Review ethics."
						m.state = "main"
					}
				}
				m.viewport.SetContent(m.output)
			}
			return m, tea.Batch(cmds...)
		}
	case tea.WindowSizeMsg:
		h, v := style.GetFrameSize()
		m.actionList.SetSize(msg.Width-h, msg.Height-v-5) // Space for status
		m.toolList.SetSize(msg.Width-h, msg.Height-v-5)
		m.scenarioList.SetSize(msg.Width-h, msg.Height-v-5)
		m.viewport.Width = msg.Width - h
		m.viewport.Height = msg.Height - v - 5
		m.progress.Width = msg.Width - h
	case statusTickMsg:
		m.status = getContainerStatus(m.distro)
		cmds = append(cmds, statusTickCmd())
	case progress.FrameMsg:
		newProgModel, cmd := m.progress.Update(msg)
		if newProgModel, ok := newProgModel.(progress.Model); ok {
			m.progress = newProgModel
		}
		cmds = append(cmds, cmd)
	}

	var cmd tea.Cmd
	switch m.state {
	case "main":
		m.actionList, cmd = m.actionList.Update(msg)
	case "select_tool":
		m.toolList, cmd = m.toolList.Update(msg)
	case "guided_lab":
		m.scenarioList, cmd = m.scenarioList.Update(msg)
	case "view_doc", "run_tool":
		m.viewport, cmd = m.viewport.Update(msg)
	}
	cmds = append(cmds, cmd)

	return m, tea.Batch(cmds...)
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
		base = m.scenarioList.View()
	case "view_doc", "run_tool":
		base = m.viewport.View()
	case "progress":
		base = m.progress.View() + "\nInitializing container..."
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

func execBph(args []string) string {
	fullArgs := append([]string{"bph"}, args...)
	cmd := exec.Command(fullArgs[0], fullArgs[1:]...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Sprintf("Backend error: %v\n%s", err, output)
	}
	return string(output)
}

func getContainerStatus(distro string) string {
	// Poll podman stats
	cmd := exec.Command("podman", "stats", "--no-stream", containerName(distro))
	output, _ := cmd.CombinedOutput()
	if strings.Contains(string(output), "No such container") {
		return fmt.Sprintf("Container %s: Stopped", distro)
	}
	// Parse simple: CPU, Mem
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

func (m *model) initContainer() tea.Cmd {
	return func() tea.Msg {
		// Simulate progress
		for i := 0.0; i <= 1.0; i += 0.1 {
			m.progress.SetPercent(i)
			time.Sleep(200 * time.Millisecond)
		}
		output := execDistrobox([]string{"create", "--name", containerName(m.distro), "--image", distroImages[m.distro]})
		m.output = output
		m.state = "main"
		return nil
	}
}

func helpText() string {
	return `BPH TUI - Educational for Pentesting
Select actions with arrows, enter to confirm.
Distro: kali or blackarch.
Guided Labs: Step-by-step learning.
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
	logDir := home + "/.hackeros/bph"
	os.MkdirAll(logDir, 0755)

	p := tea.NewProgram(initialModel(), tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Println("Error running program:", err)
		os.Exit(1)
	}
}
