{
  description = "secretctl — agent-first single-binary secret manager for macOS";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
    }:
    let
      # Pre-built tarball pulled from the GitHub release. We don't yet build
      # secretctl from source via Nix (the Zig 0.16 toolchain is not in
      # nixpkgs at the time of writing). Users who want to build from source
      # can run `zig build -Doptimize=ReleaseSafe` themselves and override
      # programs.secretctl.package.
      version = "0.5.1";
      # Placeholder; the release workflow patches this on every tag.
      # To bump manually: nix-prefetch-url --type sha256 <tarball-url>
      tarballSha256 = "40b36432284896053db79e6bf85f211615027c11ce60f577ce2c294c157b0bec";
    in
    {
      # Importable as `inputs.secretctl.homeManagerModules.default`.
      homeManagerModules.default = ./nix/home-manager.nix;
      homeManagerModules.secretctl = ./nix/home-manager.nix;

      # Overlay attaches `pkgs.secretctl` so the Home Manager module's
      # default `package = pkgs.secretctl` resolves automatically.
      overlays.default = final: _prev: {
        secretctl = final.callPackage (
          {
            stdenvNoCC,
            fetchurl,
            lib,
            ...
          }:
          stdenvNoCC.mkDerivation {
            pname = "secretctl";
            version = "0.5.1";
            src = fetchurl {
              url = "https://github.com/agent-rt/secretctl/releases/download/v0.5.1/secretctl-0.5.1-aarch64-apple-darwin.tar.gz";
              sha256 = "40b36432284896053db79e6bf85f211615027c11ce60f577ce2c294c157b0bec";
            };
            dontConfigure = true;
            dontBuild = true;
            installPhase = ''
              mkdir -p $out/bin
              install -m 0755 secretctl $out/bin/secretctl
            '';
            meta = with lib; {
              description = "Agent-first single-binary secret manager for macOS";
              homepage = "https://github.com/agent-rt/secretctl";
              license = licenses.asl20;
              platforms = [ "aarch64-darwin" ];
              maintainers = [ ];
            };
          }
        ) { };
      };
    }
    // flake-utils.lib.eachSystem [ "aarch64-darwin" ] (
      system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        secretctl = pkgs.stdenvNoCC.mkDerivation {
          pname = "secretctl";
          inherit version;
          src = pkgs.fetchurl {
            url = "https://github.com/agent-rt/secretctl/releases/download/v${version}/secretctl-${version}-aarch64-apple-darwin.tar.gz";
            sha256 = tarballSha256;
          };
          dontConfigure = true;
          dontBuild = true;
          installPhase = ''
            mkdir -p $out/bin
            install -m 0755 secretctl $out/bin/secretctl
          '';
          meta = with pkgs.lib; {
            description = "Agent-first single-binary secret manager for macOS";
            homepage = "https://github.com/agent-rt/secretctl";
            license = licenses.asl20;
            platforms = [ "aarch64-darwin" ];
            maintainers = [ ];
          };
        };
      in
      {
        packages.default = secretctl;
        packages.secretctl = secretctl;
        apps.default = flake-utils.lib.mkApp { drv = secretctl; };
      }
    );
}
