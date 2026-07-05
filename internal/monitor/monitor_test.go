package monitor

import (
	"os"
	"testing"
)

func TestProcessExists(t *testing.T) {
	// Testa com um PID válido (o nosso próprio processo)
	validPID := os.Getpid()
	if !processExists(validPID) {
		t.Errorf("processExists(%d) retornou falso para o próprio processo, esperava verdadeiro", validPID)
	}

	// Testa com um PID inválido/inexistente (um número bem alto)
	invalidPID := 999999
	if processExists(invalidPID) {
		t.Errorf("processExists(%d) retornou verdadeiro para um PID supostamente inexistente, esperava falso", invalidPID)
	}
}
