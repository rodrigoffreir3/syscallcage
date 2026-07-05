// Package logging fornece um logger JSON estruturado único para todo o
// agent-cage. Um formato só, usado por enforcer e monitor, para que log de
// produção seja grep/jq-ável sem parsear string formatada à mão.
package logging

import (
	"encoding/json"
	"os"
	"time"
)

type Entry struct {
	Timestamp string `json:"timestamp"`
	Level     string `json:"level"` // "info", "warn", "fatal"
	Component string `json:"component"`
	Message   string `json:"message"`
	PID       int    `json:"pid,omitempty"`
	EventType string `json:"event_type,omitempty"`
	Target    string `json:"target,omitempty"`
	Action    string `json:"action,omitempty"`
}

// Log escreve uma entrada JSON em stdout. Falha ao serializar nunca deve
// derrubar o programa por causa de log — em último caso, escreve algo
// simples em vez de propagar erro para cima.
func Log(e Entry) {
	e.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)
	data, err := json.Marshal(e)
	if err != nil {
		os.Stdout.WriteString(`{"level":"error","message":"falha ao serializar log"}` + "\n")
		return
	}
	os.Stdout.Write(data)
	os.Stdout.Write([]byte("\n"))
}

func Info(component, message string) {
	Log(Entry{Level: "info", Component: component, Message: message})
}

func Fatal(component, message string) {
	Log(Entry{Level: "fatal", Component: component, Message: message})
}
