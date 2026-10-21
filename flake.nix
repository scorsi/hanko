{
  description = "hanko (判子, the seal) — certificate service for a Nix-managed homelab: package, NixOS module, dev shell";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-26.05-darwin";
  # Only the M1 nixosTest uses it (two annai `soto` nameservers); never the package or the module.
  inputs.annai.url = "git+ssh://git@ishizue.tail9883f3.ts.net:2222/scorsi/annai.git";
  # Only the M1 nixosTest uses it too: its log validator checks hanko's lines (ADR 0007).
  inputs.nisshi.url = "git+ssh://git@ishizue.tail9883f3.ts.net:2222/scorsi/nisshi.git";
  inputs.nisshi.inputs.nixpkgs.follows = "nixpkgs";

  outputs =
    {
      self,
      nixpkgs,
      annai,
      nisshi,
      ...
    }:
    let
      inherit (nixpkgs) lib;
      forAllSystems = lib.genAttrs [
        "aarch64-darwin"
        "aarch64-linux"
        "x86_64-linux"
      ];
      pkgsFor = system: nixpkgs.legacyPackages.${system};

      # Only what the Go build reads: editing the docs or the Nix files doesn't rebuild the binary.
      src = lib.fileset.toSource {
        root = ./.;
        fileset = lib.fileset.unions [
          ./go.mod
          ./go.sum
          ./testdata
          (lib.fileset.fileFilter (f: f.hasExt "go") ./.)
        ];
      };

      # The example module configuration on a Linux host, whatever system evaluates it.
      nixosFor =
        linux: extra:
        lib.nixosSystem {
          modules = [
            self.nixosModules.default
            ./nix/example.nix
            extra
            { nixpkgs.hostPlatform = linux; }
          ];
        };
    in
    {
      packages = forAllSystems (system: {
        default = (pkgsFor system).callPackage ./nix/package.nix { inherit src; };
      });

      nixosModules.default = import ./nix/module.nix self;

      # The package's check phase runs `go vet` and `go test` (nix/package.nix). `module-eval`
      # evaluates the module on every system, macOS included. On Linux, `module` builds the
      # validated TOML (so `hanko check` runs on the module's output) and `module-typo` proves a
      # typo in it fails the build. `acme` is the M1 nixosTest (nix/test-acme.nix).
      checks = forAllSystems (
        system:
        let
          pkgs = pkgsFor system;
          linux = if lib.hasSuffix "-linux" system then system else "aarch64-linux";
          moduleConfig = extra: (nixosFor system extra).config.environment.etc."hanko/hanko.toml".source;
          evaluated = (nixosFor linux { }).config;
        in
        {
          default = self.packages.${system}.default;

          # Forces the configuration at eval time; the store paths are dropped so nothing is built.
          module-eval =
            assert lib.all
              (
                unit:
                unit.UMask == "0077"
                && unit.LimitCORE == 0
                && unit.CoredumpFilter == "0x0"
                && unit.ProtectKernelTunables
                && unit.ProtectKernelModules
                && unit.ProtectKernelLogs
                && unit.ProtectControlGroups
                && unit.ProtectClock
                && unit.RestrictNamespaces
                && unit.RestrictRealtime
                && unit.RestrictSUIDSGID
                && unit.LockPersonality
                && unit.SystemCallArchitectures == "native"
                && unit.TimeoutStartSec > 660
              )
              [
                evaluated.systemd.services.hanko.serviceConfig
                evaluated.systemd.services.hanko-renew.serviceConfig
              ];
            assert lib.all (c: c.group != "") evaluated.services.hanko.settings.certificates;
            pkgs.runCommand "hanko-module-eval" { } ''
              echo ${
                lib.escapeShellArg (
                  builtins.unsafeDiscardStringContext (
                    builtins.toJSON {
                      inherit (evaluated.systemd) tmpfiles;
                      unit = evaluated.systemd.services.hanko.serviceConfig;
                      renew = evaluated.systemd.services.hanko-renew.serviceConfig;
                      timer = evaluated.systemd.timers.hanko.timerConfig;
                      polkit = evaluated.security.polkit.extraConfig;
                      config = evaluated.environment.etc."hanko/hanko.toml".source.name;
                    }
                  )
                )
              } > $out
            '';
        }
        // lib.optionalAttrs (lib.hasSuffix "-linux" system) {
          module = moduleConfig { };
          module-typo = pkgs.testers.testBuildFailure (moduleConfig {
            services.hanko.settings.dns.nmaeservers = [ "203.0.113.10:53" ];
          });
          acme = import ./nix/test-acme.nix {
            inherit
              self
              annai
              nisshi
              pkgs
              ;
          };
        }
      );

      devShells = forAllSystems (
        system:
        let
          pkgs = pkgsFor system;
        in
        {
          default = pkgs.mkShellNoCC {
            packages = [
              pkgs.go
              pkgs.gopls
            ];
          };
        }
      );

      formatter = forAllSystems (system: (pkgsFor system).nixfmt-tree);
    };
}
