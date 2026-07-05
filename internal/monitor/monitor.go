package monitor

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/rodrigofreire/agent-cage/internal/enforcer"
	"github.com/rodrigofreire/agent-cage/internal/logging"
)
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -type event bpf bpf/monitor.c
const (
	EventTypeRead    = 1
	EventTypeWrite   = 2
	EventTypeExec    = 3
	EventTypeNetwork = 4

	// Intervalo de checagem de liveness do processo monitorado. Não
	// precisa ser agressivo -- é só para o agent-cage encerrar sozinho
	// quando o alvo morrer naturalmente, em vez de ficar vigiando o
	// vazio para sempre.
	livenessCheckInterval = 2 * time.Second
)

type exitReason int32

const (
	exitReasonNone exitReason = iota
	exitReasonUserRequested
	exitReasonTargetDied
)

type Monitor struct {
	objs      bpfObjects
	links     []link.Link
	ringbuf   *ringbuf.Reader
	handler   func(enforcer.Event)
	targetPID int
	closed    chan struct{}

	// exitReason é escrito tanto pela goroutine principal (via Close(),
	// disparado por sinal do usuário) quanto pela goroutine de
	// watchLiveness (quando detecta que o alvo morreu) -- as duas podem
	// correr ao mesmo tempo se o processo morrer bem na hora que o
	// usuário aperta Ctrl+C. atomic.Int32 elimina a data race sem
	// precisar de mutex.
	exitReason atomic.Int32
}

// processExists confere se um PID ainda existe no sistema, sem matar
// ninguém -- Signal(0) é o truque padrão em Unix para isso.
func processExists(pid int) bool {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	err = proc.Signal(syscall.Signal(0))
	return err == nil
}

// New inicializa o eBPF e valida, antes de qualquer coisa, que o PID alvo
// existe de verdade. Falhar aqui é muito mais barato que descobrir depois
// que o agent-cage estava vigiando um PID fantasma o tempo todo.
func New(targetPID int, handler func(enforcer.Event)) (*Monitor, error) {
	if !processExists(targetPID) {
		return nil, fmt.Errorf("PID %d não existe -- confira se o processo alvo está rodando antes de iniciar o agent-cage", targetPID)
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		logging.Log(logging.Entry{
			Level:     "warn",
			Component: "monitor",
			Message:   fmt.Sprintf("falha ao remover limite memlock (pode ser normal em kernel novo): %v", err),
		})
	}

	m := &Monitor{
		handler:   handler,
		targetPID: targetPID,
		closed:    make(chan struct{}),
	}

	if err := loadBpfObjects(&m.objs, nil); err != nil {
		return nil, fmt.Errorf("falha ao carregar objetos eBPF (rode como root ou com CAP_BPF?): %w", err)
	}

	var val uint8 = 1
	if err := m.objs.MonitoredPids.Put(uint32(targetPID), val); err != nil {
		m.Close()
		return nil, fmt.Errorf("falha ao registrar PID no bpf map: %w", err)
	}

	// Attach explícito por tracepoint. cilium/ebpf exige o tipo concreto
	// *ebpf.Program gerado pelo bpf2go para cada handler -- não dá para
	// generalizar isso numa lista/loop sem perder tipagem, então cada
	// attach é uma chamada própria, verbosa mas correta.
	kpFork, err := link.Kprobe("wake_up_new_task", m.objs.HandleWakeUpNewTask, nil)
	if err != nil {
		logging.Log(logging.Entry{Level: "warn", Component: "monitor", Message: fmt.Sprintf("falha ao atrelar kprobe wake_up_new_task: %v", err)})
	} else {
		m.links = append(m.links, kpFork)
	}

	tpExit, err := link.Tracepoint("sched", "sched_process_exit", m.objs.HandleExit, nil)
	if err != nil {
		logging.Log(logging.Entry{Level: "warn", Component: "monitor", Message: fmt.Sprintf("falha ao atrelar sched_process_exit: %v", err)})
	} else {
		m.links = append(m.links, tpExit)
	}

	kpOpenat2, err := link.Kprobe("do_sys_openat2", m.objs.HandleOpenat2, nil)
	if err != nil {
		logging.Log(logging.Entry{Level: "warn", Component: "monitor", Message: fmt.Sprintf("falha ao atrelar kprobe do_sys_openat2: %v", err)})
	} else {
		m.links = append(m.links, kpOpenat2)
	}

	kpOpen, err := link.Kprobe("do_sys_open", m.objs.HandleOpen, nil)
	if err != nil {
		logging.Log(logging.Entry{Level: "warn", Component: "monitor", Message: fmt.Sprintf("falha ao atrelar kprobe do_sys_open: %v", err)})
	} else {
		m.links = append(m.links, kpOpen)
	}

	tpExec, err := link.Tracepoint("syscalls", "sys_enter_execve", m.objs.HandleExecve, nil)
	if err != nil {
		logging.Log(logging.Entry{Level: "warn", Component: "monitor", Message: fmt.Sprintf("falha ao atrelar sys_enter_execve: %v", err)})
	} else {
		m.links = append(m.links, tpExec)
	}

	tpConnect, err := link.Tracepoint("syscalls", "sys_enter_connect", m.objs.HandleConnect, nil)
	if err != nil {
		logging.Log(logging.Entry{Level: "warn", Component: "monitor", Message: fmt.Sprintf("falha ao atrelar sys_enter_connect: %v", err)})
	} else {
		m.links = append(m.links, tpConnect)
	}

	tpSendto, err := link.Tracepoint("syscalls", "sys_enter_sendto", m.objs.HandleSendto, nil)
	if err != nil {
		logging.Log(logging.Entry{Level: "warn", Component: "monitor", Message: fmt.Sprintf("falha ao atrelar sys_enter_sendto: %v", err)})
	} else {
		m.links = append(m.links, tpSendto)
	}

	tpEnterRecvfrom, err := link.Tracepoint("syscalls", "sys_enter_recvfrom", m.objs.HandleEnterRecvfrom, nil)
	if err != nil {
		logging.Log(logging.Entry{Level: "warn", Component: "monitor", Message: fmt.Sprintf("falha ao atrelar sys_enter_recvfrom: %v", err)})
	} else {
		m.links = append(m.links, tpEnterRecvfrom)
	}

	tpExitRecvfrom, err := link.Tracepoint("syscalls", "sys_exit_recvfrom", m.objs.HandleExitRecvfrom, nil)
	if err != nil {
		logging.Log(logging.Entry{Level: "warn", Component: "monitor", Message: fmt.Sprintf("falha ao atrelar sys_exit_recvfrom: %v", err)})
	} else {
		m.links = append(m.links, tpExitRecvfrom)
	}

	rd, err := ringbuf.NewReader(m.objs.Events)
	if err != nil {
		m.Close()
		return nil, fmt.Errorf("falha ao abrir ring buffer: %w", err)
	}
	m.ringbuf = rd

	return m, nil
}

// Close encerra o Monitor a pedido explícito de quem o criou (ex: sinal
// SIGTERM recebido pelo processo principal). Se o motivo de saída já foi
// marcado por outra via (ex: watchLiveness detectando morte do alvo),
// esse Close() não sobrescreve -- o primeiro motivo registrado vale.
func (m *Monitor) Close() {
	m.exitReason.CompareAndSwap(int32(exitReasonNone), int32(exitReasonUserRequested))
	close(m.closed)
	if m.ringbuf != nil {
		m.ringbuf.Close()
	}
	for _, l := range m.links {
		l.Close()
	}
	m.objs.Close()
}

// ExitedBecauseTargetDied indica se o Monitor parou porque o processo
// monitorado terminou sozinho -- distinto de ter sido fechado por pedido
// externo ou de ter falhado de verdade. main.go usa isso para decidir se
// o encerramento é um "tudo certo, o trabalho acabou" ou uma falha real.
func (m *Monitor) ExitedBecauseTargetDied() bool {
	return exitReason(m.exitReason.Load()) == exitReasonTargetDied
}

// watchLiveness encerra o Monitor sozinho quando o processo alvo morre
// naturalmente, para o agent-cage não ficar vigiando o vazio para sempre.
func (m *Monitor) watchLiveness() {
	ticker := time.NewTicker(livenessCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-m.closed:
			return
		case <-ticker.C:
			if !processExists(m.targetPID) {
				logging.Log(logging.Entry{
					Level:     "info",
					Component: "monitor",
					Message:   "processo monitorado terminou naturalmente, encerrando",
					PID:       m.targetPID,
				})
				m.exitReason.CompareAndSwap(int32(exitReasonNone), int32(exitReasonTargetDied))
				m.ringbuf.Close()
				return
			}
		}
	}
}

// Start inicia o loop de leitura bloqueante no ring buffer. Retornar erro
// aqui é sempre fatal para o processo -- ver cmd/agent-cage/main.go, que
// trata qualquer erro de Start() como motivo para encerrar o programa
// inteiro, nunca continuar "vigiando" silenciosamente sem vigiar nada.
func (m *Monitor) Start() error {
	go m.watchLiveness()

	var event bpfEvent
	for {
		record, err := m.ringbuf.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}
			return fmt.Errorf("erro lendo ring buffer: %w", err)
		}

		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			logging.Log(logging.Entry{
				Level:     "warn",
				Component: "monitor",
				Message:   fmt.Sprintf("erro ao decodificar evento, descartado: %v", err),
			})
			continue
		}

		evt := enforcer.Event{
			PID:      int(event.Pid),
			Resolved: event.Resolved == 1,
		}

		if event.Type == EventTypeNetwork && !evt.Resolved && event.Target[0] == 0xAA {
			evt.Target = fmt.Sprintf("%d.%d.%d.%d", event.Target[1], event.Target[2], event.Target[3], event.Target[4])
			evt.Type = enforcer.EventNetwork
		} else {
			end := bytes.IndexByte(event.Target[:], 0)
			if end == -1 {
				end = len(event.Target)
			}
			targetStr := string(event.Target[:end])
			evt.Target = targetStr

			switch event.Type {
			case EventTypeRead:
				evt.Type = enforcer.EventRead
			case EventTypeWrite:
				evt.Type = enforcer.EventWrite
			case EventTypeExec:
				evt.Type = enforcer.EventSyscall
				evt.Target = "execve:" + targetStr
			case EventTypeNetwork:
				evt.Type = enforcer.EventNetwork
			}
		}

		m.handler(evt)
	}
}
