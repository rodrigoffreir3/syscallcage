package policy

import (
	"regexp"
	"strings"
)

// PathAllowed decide se um path pode ser lido/escrito, com deny_always
// tendo prioridade absoluta sobre allow — isso é zero trust de verdade,
// não decorativo. Não existe combinação de regras que burle isso.
func (p *Policy) PathAllowed(path string, forWrite bool) bool {
	// Zero trust de verdade: se a política não conseguir nem compilar
	// suas próprias regras, o comportamento seguro é negar tudo, nunca
	// abrir. Um erro de compilação aqui não deve virar "libera geral".
	if err := p.ensureCompiled(); err != nil {
		return false
	}

	for _, re := range p.compiledDeny {
		if re.MatchString(path) {
			return false
		}
	}

	allowList := p.compiledAllowRead
	if forWrite {
		allowList = p.compiledAllowWrite
	}

	for _, re := range allowList {
		if re.MatchString(path) {
			return true
		}
	}

	return false // default deny — zero trust: o que não foi explicitamente permitido, é negado
}

// DomainAllowed decide se uma conexão de rede para `domain` pode ocorrer.
func (p *Policy) DomainAllowed(domain string) bool {
	for _, allowed := range p.Network.AllowDomains {
		if strings.EqualFold(allowed, domain) {
			return true
		}
	}
	return !p.Network.DenyAllElse
}

// SyscallDenied checa se uma chamada específica (ex: "execve:/bin/sh" ou
// apenas "ptrace") está na lista de bloqueio.
func (p *Policy) SyscallDenied(syscall string) bool {
	for _, denied := range p.Syscalls.Deny {
		if denied == syscall {
			return true
		}
		// suporta bloqueio genérico: "execve" bloqueia todo execve,
		// independente do argumento
		if !strings.Contains(denied, ":") && strings.HasPrefix(syscall, denied+":") {
			return true
		}
	}
	return false
}

// globToRegex converte um padrão glob com suporte a "**" e "*" em uma
// string de expressão regular válida no Go.
func globToRegex(pattern string) string {
	var sb strings.Builder
	sb.WriteString("^")
	
	i := 0
	n := len(pattern)
	for i < n {
		if i+1 < n && pattern[i:i+2] == "**" {
			sb.WriteString(".*")
			i += 2
		} else if pattern[i] == '*' {
			sb.WriteString("[^/]*")
			i++
		} else if pattern[i] == '?' {
			sb.WriteString("[^/]")
			i++
		} else if pattern[i] == '\\' {
			if i+1 < n {
				sb.WriteString(regexp.QuoteMeta(string(pattern[i+1])))
				i += 2
			} else {
				sb.WriteString(regexp.QuoteMeta("\\"))
				i++
			}
		} else {
			sb.WriteString(regexp.QuoteMeta(string(pattern[i])))
			i++
		}
	}
	sb.WriteString("$")
	
	return sb.String()
}
