require "option_parser"

GREEN = "\e[32m"
RED = "\e[31m"
YELLOW = "\e[33m"
RESET = "\e[0m"

def main
  backend_path = File.expand_path("~/.hackeros/bph/bph-backend")
  tui_path = "/usr/bin/bph-tui"
  OptionParser.parse do |parser|
    parser.banner = "#{GREEN}Usage: bph [arguments]#{RESET}"
    parser.on("-h", "--help", "Show this help") do
      puts parser
      exit
    end
    parser.separator ""
    parser.separator "#{YELLOW}Commands:#{RESET}"
    parser.separator "  tui                Run the TUI"
    parser.separator "  completion SHELL   Generate completion script for bash or zsh"
    parser.unknown_args do |args|
      if args.empty?
        puts parser
        exit 0
      end
      command = args.shift.not_nil!
      case command
      when "tui"
        system(tui_path)
      when "completion"
        if args.empty?
          puts "#{RED}Shell required for completion#{RESET}"
          exit 1
        end
        shell = args.shift.not_nil!
        generate_completion(shell)
      else
        system(backend_path, [command] + args)
      end
    end
  end
end

def generate_completion(shell : String)
  commands = ["tui", "init", "enter", "run", "docs", "parse", "checklist", "snapshot", "stealth", "report", "network", "gateway", "clean", "detect-sandbox", "help"]
  if shell == "bash"
    puts <<-BASH
    _bph() {
      local cur prev
      cur=${COMP_WORDS[COMP_CWORD]}
      prev=${COMP_WORDS[COMP_CWORD-1]}
      COMPREPLY=( $(compgen -W "#{commands.join(" ")}" -- $cur) )
    }
    complete -F _bph bph
    BASH
  elsif shell == "zsh"
    puts <<-ZSH
    _bph() {
      local -a commands
      commands=(#{commands.map { |c| "'#{c}:description'" }.join(" ")})
      _describe 'commands' commands
    }
    compdef _bph bph
    ZSH
  else
    puts "#{RED}Unsupported shell: #{shell}#{RESET}"
  end
end

main
