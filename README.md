agent-cage
agent-cage is an eBPF-based sandbox for AI coding assistants. It enforces declarative policies (such as restricting file access and network domains) with zero modifications to the target process.
Quickstart
Compiling
Ensure you have the necessary dependencies installed (clang, llvm, and go).
Generate the eBPF Go bindings:
go generate ./...
Build the binary:
go build -o agent-cage ./cmd/agent-cage
Running
Since agent-cage loads eBPF programs, it requires root privileges (sudo).
To monitor and sandbox an existing process, pass its PID and a policy file:
sudo ./agent-cage --pid <TARGET_PID> --policy configs/exemplo-claude-code.yaml
Log Expectations
agent-cage outputs structured JSON logs. When a policy violation is detected (for example, reading a deny_always file like .env), and the policy mode is enforce, the process will be killed, and you will see a log similar to this:
{
  "level": "warn",
  "component": "enforcer",
  "message": "violação detectada, processo morto",
  "PID": 12345,
  "EventType": "read",
  "Target": "/path/to/project/.env",
  "Action": "kill"
}
If the mode is monitor, it will only log the violation without killing the process:
{
  "level": "warn",
  "component": "enforcer",
  "message": "violação detectada, permitido (modo monitor)",
  "PID": 12345,
  "EventType": "read",
  "Target": "/path/to/project/.env",
  "Action": "log"
}