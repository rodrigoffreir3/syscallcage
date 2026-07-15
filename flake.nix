{
  description = "SyscallCage - Kernel-level guardrails for autonomous AI agents";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";
  };

  outputs = { self, nixpkgs, rust-overlay }:
    let
      supportedSystems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = nixpkgs.lib.genAttrs supportedSystems;
      pkgsFor = system: import nixpkgs {
        inherit system;
        overlays = [ rust-overlay.overlays.default ];
      };
    in
    {
      packages = forAllSystems (system:
        let
          pkgs = pkgsFor system;
          rustToolchain = pkgs.rust-bin.nightly.latest.default.override {
            targets = [ "bpfel-unknown-none" ];
            extensions = [ "rust-src" ];
          };
        in
        {
          default = pkgs.rustPlatform.buildRustPackage {
            pname = "syscallcage";
            version = "0.3.0";
            src = ./.;
            cargoLock = {
              lockFile = ./Cargo.lock;
            };

            nativeBuildInputs = [
              rustToolchain
              pkgs.llvmPackages_latest.clang
              pkgs.llvmPackages_latest.llvm
              pkgs.llvmPackages_latest.lld
              pkgs.bpf-linker
            ];

            # Aya usa compilação condicional forte, desabilite testes padrões aqui
            doCheck = false;

            meta = with pkgs.lib; {
              description = "Kernel-level guardrails for autonomous AI agents via eBPF LSM";
              homepage = "https://rodrigofreire.pages.dev/syscallcage";
              license = licenses.mpl20;
              platforms = platforms.linux;
            };
          };
        }
      );

      devShells = forAllSystems (system:
        let
          pkgs = pkgsFor system;
          rustToolchain = pkgs.rust-bin.nightly.latest.default.override {
            targets = [ "bpfel-unknown-none" ];
            extensions = [ "rust-src" ];
          };
        in
        {
          default = pkgs.mkShell {
            buildInputs = [
              rustToolchain
              pkgs.llvmPackages_latest.clang
              pkgs.llvmPackages_latest.llvm
              pkgs.llvmPackages_latest.lld
              pkgs.bpf-linker
              pkgs.cargo-generate
            ];
          };
        }
      );
    };
}
