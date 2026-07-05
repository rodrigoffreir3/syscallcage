package enforcer

import (
	"errors"
	"testing"

	"github.com/rodrigofreire/agent-cage/internal/policy"
)

func policiaDeTeste() *policy.Policy {
	p := &policy.Policy{
		Mode: policy.ModeEnforce,
		Filesystem: policy.Filesystem{
			AllowRead:  []string{"/home/rodrigo/projetos/**"},
			AllowWrite: []string{"/home/rodrigo/projetos/**"},
			DenyAlways: []string{"**/.env"},
		},
		Network: policy.Network{
			AllowDomains: []string{"api.anthropic.com"},
			DenyAllElse:  true,
		},
		Syscalls: policy.Syscalls{
			Deny: []string{"ptrace"},
		},
	}
	_ = p.Validate()
	return p
}

func TestEnforcer_Allow(t *testing.T) {
	p := policiaDeTeste()
	killed := false

	enf := New(p)
	enf.KillFunc = func(pid int) error {
		killed = true
		return nil
	}

	// Evento permitido
	act, err := enf.Enforce(Event{
		PID:    1234,
		Type:   EventRead,
		Target: "/home/rodrigo/projetos/main.go",
	})

	if err != nil {
		t.Fatalf("erro inesperado: %v", err)
	}
	if act != ActionAllow {
		t.Fatalf("esperava ActionAllow, obteve %s", act)
	}
	if killed {
		t.Fatal("processo não deveria ter sido morto")
	}
}

func TestEnforcer_DenyEnforce(t *testing.T) {
	p := policiaDeTeste()
	killed := false
	killPID := 0

	enf := New(p)
	enf.KillFunc = func(pid int) error {
		killed = true
		killPID = pid
		return nil
	}

	// Evento negado (.env) em modo Enforce
	act, err := enf.Enforce(Event{
		PID:    1234,
		Type:   EventRead,
		Target: "/home/rodrigo/projetos/.env",
	})

	if err != nil {
		t.Fatalf("erro inesperado: %v", err)
	}
	if act != ActionKill {
		t.Fatalf("esperava ActionKill, obteve %s", act)
	}
	if !killed {
		t.Fatal("processo deveria ter sido morto")
	}
	if killPID != 1234 {
		t.Fatalf("esperava kill no PID 1234, obteve %d", killPID)
	}
}

func TestEnforcer_DenyMonitor(t *testing.T) {
	p := policiaDeTeste()
	p.Mode = policy.ModeMonitor
	killed := false

	enf := New(p)
	enf.KillFunc = func(pid int) error {
		killed = true
		return nil
	}

	// Evento negado em modo Monitor
	act, err := enf.Enforce(Event{
		PID:    1234,
		Type:   EventRead,
		Target: "/home/rodrigo/projetos/.env",
	})

	if err != nil {
		t.Fatalf("erro inesperado: %v", err)
	}
	if act != ActionLog {
		t.Fatalf("esperava ActionLog, obteve %s", act)
	}
	if killed {
		t.Fatal("processo não deveria ter sido morto em modo monitor")
	}
}

func TestEnforcer_KillError(t *testing.T) {
	p := policiaDeTeste()
	expectedErr := errors.New("permissão negada ao enviar sinal")

	enf := New(p)
	enf.KillFunc = func(pid int) error {
		return expectedErr
	}

	// Evento negado com falha ao matar
	_, err := enf.Enforce(Event{
		PID:    1234,
		Type:   EventRead,
		Target: "/home/rodrigo/projetos/.env",
	})

	if err == nil {
		t.Fatal("esperava erro ao falhar em matar o processo")
	}
	if !errors.Is(err, expectedErr) {
		t.Fatalf("esperava erro embrulhado contendo %v, obteve %v", expectedErr, err)
	}
}

func TestEnforcer_NetworkIPv6NaoSuportado(t *testing.T) {
	p := policiaDeTeste()
	killed := false

	enf := New(p)
	enf.KillFunc = func(pid int) error {
		killed = true
		return nil
	}

	act, err := enf.Enforce(Event{
		PID:      1234,
		Type:     EventNetwork,
		Target:   "<ipv6-nao-suportado>",
		Resolved: true,
	})

	if err != nil {
		t.Fatalf("erro inesperado: %v", err)
	}
	if act != ActionKill {
		t.Fatalf("esperava ActionKill, obteve %s", act)
	}
	if !killed {
		t.Fatal("processo deveria ter sido morto")
	}
}

func TestEnforcer_NetworkNaoResolvido(t *testing.T) {
	p := policiaDeTeste()
	killed := false

	enf := New(p)
	enf.KillFunc = func(pid int) error {
		killed = true
		return nil
	}

	act, err := enf.Enforce(Event{
		PID:      1234,
		Type:     EventNetwork,
		Target:   "api.anthropic.com",
		Resolved: false,
	})

	if err != nil {
		t.Fatalf("erro inesperado: %v", err)
	}
	if act != ActionKill {
		t.Fatalf("esperava ActionKill, obteve %s", act)
	}
	if !killed {
		t.Fatal("processo deveria ter sido morto")
	}
}

func TestEnforcer_NetworkAllowed(t *testing.T) {
	p := policiaDeTeste()
	killed := false

	enf := New(p)
	enf.KillFunc = func(pid int) error {
		killed = true
		return nil
	}

	act, err := enf.Enforce(Event{
		PID:      1234,
		Type:     EventNetwork,
		Target:   "api.anthropic.com",
		Resolved: true,
	})

	if err != nil {
		t.Fatalf("erro inesperado: %v", err)
	}
	if act != ActionAllow {
		t.Fatalf("esperava ActionAllow, obteve %s", act)
	}
	if killed {
		t.Fatal("processo não deveria ter sido morto")
	}
}

func TestEnforcer_EventSyscall(t *testing.T) {
	p := policiaDeTeste()
	killed := false

	enf := New(p)
	enf.KillFunc = func(pid int) error {
		killed = true
		return nil
	}

	act, err := enf.Enforce(Event{
		PID:    1234,
		Type:   EventSyscall,
		Target: "ptrace",
	})

	if err != nil {
		t.Fatalf("erro inesperado: %v", err)
	}
	if act != ActionKill {
		t.Fatalf("esperava ActionKill, obteve %s", act)
	}
	if !killed {
		t.Fatal("processo deveria ter sido morto")
	}
}

func TestEnforcer_SyscallAllowed(t *testing.T) {
	p := policiaDeTeste()
	killed := false

	enf := New(p)
	enf.KillFunc = func(pid int) error {
		killed = true
		return nil
	}

	act, err := enf.Enforce(Event{
		PID:    1234,
		Type:   EventSyscall,
		Target: "open",
	})

	if err != nil {
		t.Fatalf("erro inesperado: %v", err)
	}
	if act != ActionAllow {
		t.Fatalf("esperava ActionAllow, obteve %s", act)
	}
	if killed {
		t.Fatal("processo não deveria ter sido morto")
	}
}

func TestEnforcer_EventWriteAllowed(t *testing.T) {
	p := policiaDeTeste()
	killed := false

	enf := New(p)
	enf.KillFunc = func(pid int) error {
		killed = true
		return nil
	}

	act, err := enf.Enforce(Event{
		PID:    1234,
		Type:   EventWrite,
		Target: "/home/rodrigo/projetos/main.go",
	})

	if err != nil {
		t.Fatalf("erro inesperado: %v", err)
	}
	if act != ActionAllow {
		t.Fatalf("esperava ActionAllow, obteve %s", act)
	}
	if killed {
		t.Fatal("processo não deveria ter sido morto")
	}
}

func TestEnforcer_UnknownEventType(t *testing.T) {
	p := policiaDeTeste()
	enf := New(p)

	act, err := enf.Enforce(Event{
		PID:  1234,
		Type: EventType("unknown_event_type"),
	})

	if err == nil {
		t.Fatal("esperava erro para tipo de evento desconhecido")
	}
	// Fail-closed, não fail-open: tipo de evento que o Enforcer não
	// reconhece é bug de programação (novo EventType adicionado sem
	// atualizar o switch), não motivo para liberar por padrão. Zero trust
	// de verdade nunca abre mão silenciosamente diante do desconhecido.
	if act == ActionAllow {
		t.Fatal("evento de tipo desconhecido NUNCA deveria resultar em ActionAllow (fail-closed esperado)")
	}
}
