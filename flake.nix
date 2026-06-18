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
			checks.pytest = pkgs.python312.pkgs.buildPythonPackage {
				pname = "endpoint-tests";
				version = "0.1.0";
				format = "other";
				src = ./.;
				
				propagatedBuildInputs = [
					pkgs.python312.pkgs.fastapi
					pkgs.python312.pkgs.httpx
					pkgs.python312.pkgs.uvicorn
					pkgs.python312.pkgs.websockets
					pkgs.python312.pkgs.wsproto

					config.packages.endpoint-openpgp-sequoia
				];

				buildInputs = [
					pkgs.nettle
					pkgs.gmp
					pkgs.openssl
				];

				nativeCheckInputs = [
					pkgs.coreutils
					pkgs.python312.pkgs.pytestCheckHook
					pkgs.python312.pkgs.pytest-asyncio
					pkgs.python312.pkgs.trustme
				];

				pytestFlags = [
					"-vv"
					"--endpoint-trace"
				];

				preCheck = ''
					export PATH="${config.packages.endpoint-openpgp-sequoia}/bin:$PATH"
					export SEQUOIA_BINARY_PATH="${config.packages.endpoint-openpgp-sequoia}/bin/endpoint-openpgp-sequoia"
				'';
						
				dontBuild = true;
				dontInstall = true;
			};
			
			packages.endpoint-openpgp-sequoia = pkgs.rustPlatform.buildRustPackage {
				pname = "endpoint-openpgp-sequoia";
				version = "0.1.0";

				src = ./openpgp-sequoia;
				cargoHash = "sha256-d1RZYUGO3Nnl9J19OWqdhMWbqeijgYcp77SsRAu+XzI=";

				nativeBuildInputs = [
					pkgs.pkg-config
				];

				buildInputs = [
					pkgs.nettle
					pkgs.gmp
					pkgs.openssl
				];
			};

			packages.endpoint = pkgs.python312.pkgs.buildPythonApplication {
				pname = "endpoint-protocol";
				version = "0.1.0";
				format = "pyproject";

				src = ./.;

				nativeBuildInputs = [
					pkgs.python312.pkgs.setuptools
					pkgs.python312.pkgs.wheel
					pkgs.python312.pkgs.pythonRelaxDepsHook
				];

				pythonRelaxDeps = [
					"fastapi"
					"wsproto"
				];
				
				pythonRemoveDeps = [
					"endpoint-openpgp-sequoia"
				];

				doCheck = false;

				propagatedBuildInputs = [
					pkgs.python312.pkgs.fastapi
					pkgs.python312.pkgs.httpx
					pkgs.python312.pkgs.uvicorn
					pkgs.python312.pkgs.websockets
					pkgs.python312.pkgs.wsproto

					config.packages.endpoint-openpgp-sequoia
				];

				buildInputs = [
					pkgs.nettle
					pkgs.gmp
					pkgs.openssl
				];
				
				meta.mainProgram = "endpoint";
			};

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

				shellHook = ''
					export PKG_CONFIG_PATH="${pkgs.openssl.dev}/lib/pkgconfig:${pkgs.nettle}/lib/pkgconfig"
					export PATH="${config.packages.endpoint-openpgp-sequoia}/bin:$PATH"
					export SEQUOIA_BINARY_PATH="${config.packages.endpoint-openpgp-sequoia}/bin/endpoint-openpgp-sequoia"
				'';
			};
		};
	};
}
