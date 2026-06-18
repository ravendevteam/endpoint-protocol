{
	inputs.nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
	inputs.flake-parts.url = "github:hercules-ci/flake-parts";

	outputs = inputs @ { flake-parts, ... }:
	flake-parts.lib.mkFlake {
		inherit inputs;
	} {
		systems = [
			"x86_64-linux"
			"x86_64-darwin"
			"aarch64-linux"
			"aarch64-darwin"
		];
		
		perSystem = { config, pkgs, system, ... }: {
			devShells.default = pkgs.mkShell {
				nativeBuildInputs = [
					pkgs.nixd
					pkgs.nixpkgs-fmt
					pkgs.clippy
					pkgs.cargo
					pkgs.rustc
					pkgs.rust-analyzer
					pkgs.lld
					pkgs.pkg-config
					
					pkgs.nettle
					pkgs.gmp
					
					(pkgs.python312.withPackages (pkgs: [
						pkgs.fastapi
						pkgs.httpx
						pkgs.uvicorn
						pkgs.websockets
						pkgs.wsproto
						pkgs.pytest
						pkgs.pytest-asyncio
						pkgs.trustme
					]))
				];
				
				buildInputs = [
					pkgs.openssl
				];
				
				shellHook = ''
					
				'';
			};
		};
	};
}