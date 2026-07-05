// Package policy define a estrutura declarativa de regras que o agent-cage
// aplica sobre um processo monitorado. Parsing e validação puros — nenhuma
// dependência de eBPF ou kernel aqui, de propósito (testável em qualquer
// máquina, sem privilégio).
package policy

import (
	"fmt"
	"os"
	"regexp"
	"sync"

	"gopkg.in/yaml.v3"
)

type Mode string

const (
	ModeEnforce Mode = "enforce"
	ModeMonitor Mode = "monitor"
)

type Filesystem struct {
	AllowRead  []string `yaml:"allow_read"`
	AllowWrite []string `yaml:"allow_write"`
	DenyAlways []string `yaml:"deny_always"`
}

type Network struct {
	AllowDomains []string `yaml:"allow_domains"`
	DenyAllElse  bool     `yaml:"deny_all_else"`
}

type Syscalls struct {
	Deny []string `yaml:"deny"`
}

type Policy struct {
	Mode       Mode       `yaml:"mode"`
	Filesystem Filesystem `yaml:"filesystem"`
	Network    Network    `yaml:"network"`
	Syscalls   Syscalls   `yaml:"syscalls"`

	compileOnce        sync.Once
	compileErr         error
	compiledDeny       []*regexp.Regexp
	compiledAllowRead  []*regexp.Regexp
	compiledAllowWrite []*regexp.Regexp
}

// ensureCompiled garante que os regex derivados existem, não importa como
// a Policy foi construída (Load(), struct literal em teste, etc). Isso
// elimina a classe inteira de bug "esqueci de chamar Validate() depois de
// construir a struct" — a política nunca fica em estado inconsistente
// silenciosamente. sync.Once garante que a compilação roda uma única vez
// mesmo sob concorrência.
func (p *Policy) ensureCompiled() error {
	p.compileOnce.Do(func() {
		var err error
		if p.compiledDeny, err = compileGlobs(p.Filesystem.DenyAlways); err != nil {
			p.compileErr = fmt.Errorf("erro em deny_always: %w", err)
			return
		}
		if p.compiledAllowRead, err = compileGlobs(p.Filesystem.AllowRead); err != nil {
			p.compileErr = fmt.Errorf("erro em allow_read: %w", err)
			return
		}
		if p.compiledAllowWrite, err = compileGlobs(p.Filesystem.AllowWrite); err != nil {
			p.compileErr = fmt.Errorf("erro em allow_write: %w", err)
			return
		}
	})
	return p.compileErr
}

// Load lê e valida uma política a partir de um arquivo YAML.
func Load(path string) (*Policy, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("policy: falha ao ler %s: %w", path, err)
	}

	var p Policy
	if err := yaml.Unmarshal(raw, &p); err != nil {
		return nil, fmt.Errorf("policy: yaml inválido em %s: %w", path, err)
	}

	if err := p.Validate(); err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}

	return &p, nil
}

// Validate garante que a política é minimamente sã antes de ser aplicada.
// Falhar cedo aqui evita comportamento surpresa em produção.
func (p *Policy) Validate() error {
	if p.Mode != ModeEnforce && p.Mode != ModeMonitor {
		return fmt.Errorf("mode deve ser 'enforce' ou 'monitor', recebido: %q", p.Mode)
	}

	if len(p.Filesystem.AllowRead) == 0 && len(p.Filesystem.AllowWrite) == 0 {
		return fmt.Errorf("política sem nenhum allow_read/allow_write definido — provavelmente erro de configuração, não intenção real")
	}

	// Valida sintaxe dos padrões glob cedo (fail-fast), mas a compilação
	// real e o cache dela ficam a cargo de ensureCompiled(), chamado
	// automaticamente por PathAllowed. Isso significa que Validate() pode
	// ser chamado zero, uma, ou várias vezes sem nunca deixar a Policy em
	// estado inconsistente.
	return p.ensureCompiled()
}

// compileGlobs traduz uma lista de padrões glob para expressões regulares e as compila.
func compileGlobs(patterns []string) ([]*regexp.Regexp, error) {
	var regexes []*regexp.Regexp
	for _, pattern := range patterns {
		reStr := globToRegex(pattern)
		re, err := regexp.Compile(reStr)
		if err != nil {
			return nil, fmt.Errorf("padrão '%s' (regex: %s) é inválido: %w", pattern, reStr, err)
		}
		regexes = append(regexes, re)
	}
	return regexes, nil
}
