package policy

import (
	"os"
	"testing"
)

func policiaDeTeste() *Policy {
	p := &Policy{
		Mode: ModeEnforce,
		Filesystem: Filesystem{
			AllowRead:  []string{"/home/rodrigo/projetos/**"},
			AllowWrite: []string{"/home/rodrigo/projetos/**"},
			DenyAlways: []string{"**/.env", "**/.ssh/**"},
		},
		Network: Network{
			AllowDomains: []string{"api.anthropic.com", "github.com"},
			DenyAllElse:  true,
		},
		Syscalls: Syscalls{
			Deny: []string{"execve:/bin/sh", "ptrace"},
		},
	}
	return p
}

func TestPathAllowed_DenyAlwaysVenceQualquerAllow(t *testing.T) {
	p := policiaDeTeste()

	// mesmo estando "dentro" do diretório permitido, .env é sempre negado
	if p.PathAllowed("/home/rodrigo/projetos/app/.env", false) {
		t.Fatal("deny_always deveria vencer allow_read, mas path foi permitido")
	}
}

func TestPathAllowed_DentroDoAllowList(t *testing.T) {
	p := policiaDeTeste()

	if !p.PathAllowed("/home/rodrigo/projetos/app/main.go", false) {
		t.Fatal("path dentro do allow_read deveria ser permitido")
	}
}

func TestPathAllowed_ForaDoAllowListEDefaultDeny(t *testing.T) {
	p := policiaDeTeste()

	// zero trust: path não listado em lugar nenhum -> negado por padrão
	if p.PathAllowed("/etc/passwd", false) {
		t.Fatal("path fora de qualquer allow_list deveria ser negado por padrão (zero trust)")
	}
}

func TestPathAllowed_SSHSempreNegado(t *testing.T) {
	p := policiaDeTeste()

	if p.PathAllowed("/home/rodrigo/.ssh/id_rsa", false) {
		t.Fatal(".ssh deveria estar em deny_always")
	}
}

func TestDomainAllowed_DominioNaListaPermitido(t *testing.T) {
	p := policiaDeTeste()

	if !p.DomainAllowed("api.anthropic.com") {
		t.Fatal("domínio na allow_list deveria ser permitido")
	}
}

func TestDomainAllowed_DominioForaDaListaNegadoQuandoDenyAllElse(t *testing.T) {
	p := policiaDeTeste()

	if p.DomainAllowed("evil-c2-server.ru") {
		t.Fatal("domínio fora da allow_list, com deny_all_else, deveria ser negado")
	}
}

func TestDomainAllowed_SemDenyAllElsePermiteQualquerCoisa(t *testing.T) {
	p := policiaDeTeste()
	p.Network.DenyAllElse = false

	if !p.DomainAllowed("qualquer-dominio.com") {
		t.Fatal("com deny_all_else=false, qualquer domínio deveria passar")
	}
}

func TestSyscallDenied_MatchExatoComArgumento(t *testing.T) {
	p := policiaDeTeste()

	if !p.SyscallDenied("execve:/bin/sh") {
		t.Fatal("execve:/bin/sh deveria estar bloqueado")
	}

	// execve de outro binário não listado explicitamente não deveria cair
	// nessa regra específica (regra é sobre o /bin/sh, não sobre execve genérico)
	if p.SyscallDenied("execve:/usr/bin/go") {
		t.Fatal("execve de binário não listado não deveria ser bloqueado por essa regra")
	}
}

func TestSyscallDenied_BloqueioGenericoSemArgumento(t *testing.T) {
	p := policiaDeTeste()

	// "ptrace" na policy, sem ":", deve bloquear qualquer variante de ptrace
	if !p.SyscallDenied("ptrace:PTRACE_ATTACH") {
		t.Fatal("regra genérica 'ptrace' deveria bloquear qualquer variante")
	}
}

func TestValidate_ModeInvalidoFalha(t *testing.T) {
	p := &Policy{Mode: "yolo"}
	if err := p.Validate(); err == nil {
		t.Fatal("mode inválido deveria falhar validação")
	}
}

func TestValidate_SemAllowListNenhumaFalha(t *testing.T) {
	p := &Policy{Mode: ModeEnforce}
	if err := p.Validate(); err == nil {
		t.Fatal("política sem nenhum allow_read/allow_write deveria falhar validação (provável erro de config)")
	}
}

func TestPathAllowed_FuncionaSemChamarValidateManualmente(t *testing.T) {
	// Regressão: uma Policy construída por struct literal, sem NUNCA
	// chamar Validate() ou qualquer outro método antes, precisa funcionar
	// corretamente na primeira chamada a PathAllowed. Zero trust não pode
	// depender de alguém lembrar de inicializar algo antes.
	p := &Policy{
		Filesystem: Filesystem{
			AllowRead: []string{"/home/rodrigo/projetos/**"},
		},
	}

	if !p.PathAllowed("/home/rodrigo/projetos/main.go", false) {
		t.Fatal("PathAllowed deveria funcionar mesmo sem chamada prévia a Validate()")
	}
}

func TestPathAllowed_WriteDiferenciado(t *testing.T) {
	p := policiaDeTeste()
	p.Filesystem.AllowRead = []string{"/public/**"}
	p.Filesystem.AllowWrite = []string{"/private/**"}
	_ = p.Validate()

	if !p.PathAllowed("/public/file.txt", false) {
		t.Fatal("leitura em /public deveria ser permitida")
	}
	if p.PathAllowed("/public/file.txt", true) {
		t.Fatal("escrita em /public deveria ser negada")
	}

	if !p.PathAllowed("/private/file.txt", true) {
		t.Fatal("escrita em /private deveria ser permitida")
	}
	if p.PathAllowed("/private/file.txt", false) {
		t.Fatal("leitura em /private deveria ser negada")
	}
}

func TestGlobToRegex_Especiais(t *testing.T) {
	testCases := []struct {
		glob     string
		expected string
	}{
		{"*.txt", "^[^/]*\\.txt$"},
		{"dir/?/file", "^dir/[^/]/file$"},
		{"dir\\file", "^dirfile$"},
		{"dir\\", "^dir\\\\$"},
	}

	for _, tc := range testCases {
		res := globToRegex(tc.glob)
		if res != tc.expected {
			t.Errorf("globToRegex(%q) = %q, expected %q", tc.glob, res, tc.expected)
		}
	}
}

func TestLoad_ArquivoInexistente(t *testing.T) {
	_, err := Load("nao-existe.yaml")
	if err == nil {
		t.Fatal("esperava erro ao tentar carregar arquivo inexistente")
	}
}

func TestLoad_YamlInvalido(t *testing.T) {
	f, err := os.CreateTemp("", "invalid*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())

	f.WriteString("invalid: yaml: :")
	f.Close()

	_, err = Load(f.Name())
	if err == nil {
		t.Fatal("esperava erro com YAML invalido")
	}
}

func TestLoad_PolicyInvalida(t *testing.T) {
	f, err := os.CreateTemp("", "invalid_policy*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())

	f.WriteString("mode: yolo\nfilesystem:\n  allow_read: ['/tmp']\n")
	f.Close()

	_, err = Load(f.Name())
	if err == nil {
		t.Fatal("esperava erro com policy inválida (mode yolo)")
	}
}

func TestLoad_PolicyValida(t *testing.T) {
	f, err := os.CreateTemp("", "valid_policy*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())

	f.WriteString("mode: enforce\nfilesystem:\n  allow_read: ['/tmp']\n")
	f.Close()

	p, err := Load(f.Name())
	if err != nil {
		t.Fatalf("erro inesperado: %v", err)
	}
	if p.Mode != ModeEnforce {
		t.Fatalf("esperava mode enforce, obteve %s", p.Mode)
	}
}
