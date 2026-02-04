require "option_parser"

def main
  backend_path = File.expand_path("~/.hackeros/bph/backend")
  tui_path = "/usr/bin/bph-tui"

  OptionParser.parse do |parser|
    parser.banner = "Usage: bph <command> [arguments]"
    parser.on("tui", "Run the TUI") do
      system(tui_path)
      exit
    end
    parser.on("-h", "--help", "Show this help") do
      puts parser
      exit
    end
    parser.unknown_args do |args|
      if args.empty?
        puts parser
        exit 1
      end
      command = args.shift
      system(backend_path, [command] + args)
    end
  end
end

main if __FILE__ == PROGRAM_NAME

