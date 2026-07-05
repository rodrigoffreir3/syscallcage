package enforcer

import (
	"fmt"
	"os"

	"github.com/rodrigofreire/agent-cage/internal/logging"
	"github.com/rodrigofreire/agent-cage/internal/policy"
)

type Action string

const (
	ActionAllow Action = "allow"
	ActionLog   Action = "log"
	ActionKill  Action = "kill"
)

type EventType string

const (
	EventRead    EventType = "read"
	EventWrite   EventType = "write"
	EventNetwork EventType = "network"
	EventSyscall EventType = "syscall"
)

type Event struct {
	PID      int
	Type     EventType
	Target   string
	Resolved bool
}

type Enforcer struct {
	Policy   *policy.Policy
	KillFunc func(pid int) error
}

// New cria um Enforcer com a implementação real de kill (SIGKILL via
// os.Process). Log é sempre via internal/logging — não é mais injetável
// como função solta, porque isso deixava aberto formato de log
// inconsistente dependendo de quem construía o Enforcer.
func New(p *policy.Policy) *Enforcer {
	return &Enforcer{
		Policy: p,
		KillFunc: func(pid int) error {
			proc, err := os.FindProcess(pid)
			if err != nil {
				return err
			}
			return proc.Signal(os.Kill)
		},
	}
}

// Enforce decide qual ação tomar com base em um evento e sempre loga em
// JSON estruturado, tanto em caminho feliz (allow) quanto em violação.
func (e *Enforcer) Enforce(event Event) (Action, error) {
	logging.Log(logging.Entry{
		Level:     "info",
		Component: "enforcer_debug",
		Message:   "evento recebido",
		PID:       event.PID,
		EventType: string(event.Type),
		Target:    event.Target,
	})

	var allowed bool
	switch event.Type {
	case EventRead:
		allowed = e.Policy.PathAllowed(event.Target, false)
	case EventWrite:
		allowed = e.Policy.PathAllowed(event.Target, true)
	case EventNetwork:
		switch {
		case event.Target == "<ipv6-nao-suportado>":
			allowed = false
		case !event.Resolved:
			// Zero trust: conexão sem domínio resolvido (IP cru, sem DNS
			// prévio capturado) é tratada como suspeita por padrão, nunca
			// permitida silenciosamente.
			allowed = false
		default:
			allowed = e.Policy.DomainAllowed(event.Target)
		}
	case EventSyscall:
		allowed = !e.Policy.SyscallDenied(event.Target)
	default:
		logging.Log(logging.Entry{
			Level:     "warn",
			Component: "enforcer",
			Message:   "tipo de evento desconhecido, negado por padrão",
			PID:       event.PID,
			EventType: string(event.Type),
			Target:    event.Target,
		})
		return ActionLog, fmt.Errorf("tipo de evento desconhecido: %s", event.Type)
	}

	if allowed {
		return ActionAllow, nil
	}

	// Violação detectada — decide entre matar (enforce) ou só logar (monitor).
	if e.Policy.Mode == policy.ModeEnforce {
		err := e.KillFunc(event.PID)
		if err != nil {
			logging.Log(logging.Entry{
				Level:     "fatal",
				Component: "enforcer",
				Message:   "violação detectada mas falha ao matar processo",
				PID:       event.PID,
				EventType: string(event.Type),
				Target:    event.Target,
				Action:    string(ActionKill),
			})
			return ActionKill, fmt.Errorf("falha ao aplicar enforce: %w", err)
		}

		logging.Log(logging.Entry{
			Level:     "warn",
			Component: "enforcer",
			Message:   "violação detectada, processo morto",
			PID:       event.PID,
			EventType: string(event.Type),
			Target:    event.Target,
			Action:    string(ActionKill),
		})
		return ActionKill, nil
	}

	logging.Log(logging.Entry{
		Level:     "warn",
		Component: "enforcer",
		Message:   "violação detectada, permitido (modo monitor)",
		PID:       event.PID,
		EventType: string(event.Type),
		Target:    event.Target,
		Action:    string(ActionLog),
	})
	return ActionLog, nil
}
