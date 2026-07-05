package main

import (
	"flag"
	"os"
	"os/signal"
	"syscall"

	"github.com/rodrigofreire/agent-cage/internal/enforcer"
	"github.com/rodrigofreire/agent-cage/internal/logging"
	"github.com/rodrigofreire/agent-cage/internal/monitor"
	"github.com/rodrigofreire/agent-cage/internal/policy"
)

const component = "main"

func main() {
	pidFlag := flag.Int("pid", 0, "PID do processo alvo a monitorar (obrigatório)")
	policyFlag := flag.String("policy", "", "Caminho para o arquivo YAML de política (obrigatório)")
	flag.Parse()

	if *pidFlag == 0 {
		logging.Fatal(component, "flag --pid é obrigatória e deve ser diferente de zero")
		os.Exit(1)
	}
	if *policyFlag == "" {
		logging.Fatal(component, "flag --policy é obrigatória")
		os.Exit(1)
	}

	pol, err := policy.Load(*policyFlag)
	if err != nil {
		logging.Fatal(component, "falha ao carregar política: "+err.Error())
		os.Exit(1)
	}

	enf := enforcer.New(pol)

	handler := func(evt enforcer.Event) {
		if _, err := enf.Enforce(evt); err != nil {
			logging.Log(logging.Entry{
				Level:     "warn",
				Component: component,
				Message:   "erro ao processar evento: " + err.Error(),
				PID:       evt.PID,
				EventType: string(evt.Type),
				Target:    evt.Target,
			})
		}
	}

	// monitor.New já valida internamente que o PID existe antes de
	// prosseguir -- ver internal/monitor/monitor.go, processExists().
	mon, err := monitor.New(*pidFlag, handler)
	if err != nil {
		logging.Fatal(component, "falha ao inicializar monitor: "+err.Error())
		os.Exit(1)
	}

	logging.Log(logging.Entry{
		Level:     "info",
		Component: component,
		Message:   "agent-cage iniciado",
		PID:       *pidFlag,
	})

	// monitorDone é fechado quando Start() retorna, seja por Close()
	// externo (SIGTERM/SIGINT do usuário) ou por falha real do eBPF
	// (ring buffer quebrou, kernel resetou algo). A distinção entre os
	// dois casos importa: se foi o usuário que pediu para parar, sai
	// limpo (código 0). Se foi falha real do monitor, o programa
	// precisa morrer também com erro -- nunca fica de pé fingindo que
	// ainda está vigiando algo que já parou de funcionar por baixo.
	monitorErrCh := make(chan error, 1)
	go func() {
		monitorErrCh <- mon.Start()
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	select {
	case <-sigCh:
		logging.Log(logging.Entry{
			Level:     "info",
			Component: component,
			Message:   "sinal de encerramento recebido, desligando",
			PID:       *pidFlag,
		})
		mon.Close()
		<-monitorErrCh // espera Start() retornar de verdade antes de sair

	case err := <-monitorErrCh:
		// Start() retornou sem que o usuário tenha pedido nada. Isso
		// tem duas causas possíveis, e main.go trata cada uma
		// diferente:
		//
		//   1. O processo monitorado morreu sozinho (watchLiveness
		//      detectou e fechou o ringbuf de propósito) -- isso é
		//      sucesso: o trabalho de vigiar acabou porque não há mais
		//      o que vigiar. Sai com código 0.
		//
		//   2. Qualquer outro motivo (ring buffer quebrou, kernel
		//      resetou algo, erro real de leitura) -- isso é falha.
		//      Um agent-cage que não lê mais eventos não está mais
		//      protegendo ninguém, e continuar de pé nesse estado é
		//      pior do que nunca ter iniciado. Sai com erro.
		mon.Close()

		if mon.ExitedBecauseTargetDied() {
			logging.Log(logging.Entry{
				Level:     "info",
				Component: component,
				Message:   "processo monitorado encerrou, agent-cage finalizado normalmente",
				PID:       *pidFlag,
			})
			return
		}

		msg := "monitor encerrou inesperadamente, agent-cage não está mais protegendo o PID"
		if err != nil {
			msg += ": " + err.Error()
		}
		logging.Fatal(component, msg)
		os.Exit(1)
	}

	logging.Log(logging.Entry{
		Level:     "info",
		Component: component,
		Message:   "agent-cage encerrado",
		PID:       *pidFlag,
	})
}
