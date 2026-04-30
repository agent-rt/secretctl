{
  description = "secretctl — agent-first single-binary secret manager for macOS";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    zig-overlay.url = "github:mitchellh/zig-overlay";
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
      zig-overlay,
    }:
    {
      # Importable as `inputs.secretctl.homeManagerModules.default`.
      homeManagerModules.default = ./nix/home-manager.nix;
      homeManagerModules.secretctl = ./nix/home-manager.nix;

      # Overlay attaches `pkgs.secretctl`. Resolves to the per-system package
      # built from this very source tree, so there is no release tarball to
      # fetch and no sha256 to keep in sync.
      overlays.default = final: _prev: {
        secretctl = self.packages.${final.system}.default;
      };
    }
    // flake-utils.lib.eachSystem [ "aarch64-darwin" ] (
      system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        zig = zig-overlay.packages.${system}."0.16.0";
        secretctl = pkgs.stdenvNoCC.mkDerivation {
          pname = "secretctl";
          version = "0.5.1";

          # `self` is the flake source tree. Anyone pinning to a tag, branch,
          # or commit gets exactly that source — no release tarball involved.
          src = self;

          # Modern nixpkgs darwin auto-resolves system frameworks via the
          # apple-sdk package; we just need it in build inputs (no per-
          # framework attrs since darwin.apple_sdk.frameworks was removed).
          nativeBuildInputs = [ zig ];

          # apple-sdk must be a (host-context) buildInput so its setup-hook
          # exports `SDKROOT` (not `SDKROOT_FOR_BUILD`).
          buildInputs = [ pkgs.apple-sdk_14 ];

          dontConfigure = true;

          buildPhase = ''
            runHook preBuild
            export ZIG_GLOBAL_CACHE_DIR=$TMPDIR/zig-cache
            # apple-sdk_14's setup-hook exports SDKROOT; Zig needs it as --sysroot
            # so it can resolve `-framework Security` etc. against the SDK's
            # System/Library/Frameworks tree.
            zig build -Doptimize=ReleaseSafe \
              --sysroot "$SDKROOT" \
              --cache-dir $TMPDIR/zig-build-cache \
              --global-cache-dir $ZIG_GLOBAL_CACHE_DIR
            runHook postBuild
          '';

          installPhase = ''
            runHook preInstall
            mkdir -p $out/bin
            install -m0755 zig-out/bin/secretctl $out/bin/secretctl
            runHook postInstall
          '';

          meta = with pkgs.lib; {
            description = "Agent-first single-binary secret manager for macOS";
            homepage = "https://github.com/agent-rt/secretctl";
            license = licenses.asl20;
            platforms = [ "aarch64-darwin" ];
            mainProgram = "secretctl";
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
