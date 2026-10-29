{
  description = "hanko (判子, the seal) — certificate service for a Nix-managed homelab: package, NixOS module, dev shell";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-26.05-darwin";
  # Only the M1 nixosTest uses it (two annai `soto` nameservers); never the package or the module.
  inputs.annai.url = "git+ssh://git@forgejo.uchi.scorsi.dev:2222/scorsi/annai.git";
  # Only the M1 nixosTest uses it too: its log validator checks hanko's lines (ADR 0007).
  inputs.nisshi.url = "git+ssh://git@forgejo.uchi.scorsi.dev:2222/scorsi/nisshi.git";
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
            self.nixosModules.ca
            ./nix/example.nix
            extra
            { nixpkgs.hostPlatform = linux; }
          ];
        };
    in
    {
      # One build holds both binaries; hanko-ca only changes what `lib.getExe` returns.
      packages = forAllSystems (
        system:
        let
          hanko = (pkgsFor system).callPackage ./nix/package.nix { inherit src; };
        in
        {
          default = hanko;
          inherit hanko;
          # Same derivation; `//` changes only the attribute set, not the build.
          hanko-ca = hanko // {
            meta = hanko.meta // {
              mainProgram = "hanko-ca";
            };
          };
        }
      );

      nixosModules.default = import ./nix/module.nix self;
      nixosModules.ca = import ./nix/ca.nix self;

      # The package's check phase runs `go vet` and `go test` (nix/package.nix). `module-eval`
      # evaluates both modules on every system, macOS included. On Linux, `module` and `ca-module`
      # build the validated TOML (so `hanko check` and `hanko-ca check` run on the modules' output)
      # and `module-typo` proves a typo in it fails the build. `acme` is the M1 nixosTest
      # (nix/test-acme.nix), `internal` the v1 one (nix/test-internal.nix). `buf-lint` lints the protos and `proto-generated` fails when the
      # committed Go code differs from `buf generate proto`.
      checks = forAllSystems (
        system:
        let
          pkgs = pkgsFor system;
          linux = if lib.hasSuffix "-linux" system then system else "aarch64-linux";
          moduleConfig = extra: (nixosFor system extra).config.environment.etc."hanko/hanko.toml".source;
          evaluated = (nixosFor linux { }).config;
          ca = evaluated.systemd.services.hanko-ca.serviceConfig;
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
                && unit.CapabilityBoundingSet == ""
                && unit.NoNewPrivileges
                && unit.ProtectSystem == "strict"
                && unit.ProtectHome
                && unit.PrivateTmp
                && unit.PrivateDevices
                &&
                  unit.RestrictAddressFamilies == [
                    "AF_INET"
                    "AF_INET6"
                    "AF_UNIX"
                  ]
                && !(unit ? DynamicUser)
              )
              [
                evaluated.systemd.services.hanko.serviceConfig
                evaluated.systemd.services.hanko-renew.serviceConfig
                evaluated.systemd.services.hanko-ca.serviceConfig
              ];
            assert lib.all (unit: unit.TimeoutStartSec > 660) [
              evaluated.systemd.services.hanko.serviceConfig
              evaluated.systemd.services.hanko-renew.serviceConfig
            ];
            # hanko-ca: its own static user, persists nothing (ADR 0004, ADR 0005).
            assert
              ca.User == "hanko-ca"
              && evaluated.users.users.hanko-ca.isSystemUser
              && !(ca ? StateDirectory)
              && lib.hasSuffix "/bin/hanko-ca serve /etc/hanko/ca.toml" ca.ExecStart;
            assert lib.all (c: c.group != "") evaluated.services.hanko.settings.certificates;
            # The internal issuer's table and keys reach the file (ADR 0002, ADR 0004).
            assert
              evaluated.services.hanko.settings.internal.ca == "[fd12:3456:789a::1]:4900"
              && lib.any (
                c: c.issuer == "internal" && c.spiffe_id == "spiffe://uchi.example.org/vm/api" && !(c ? hosts)
              ) evaluated.services.hanko.settings.certificates;
            pkgs.runCommand "hanko-module-eval" { } ''
              echo ${
                lib.escapeShellArg (
                  builtins.unsafeDiscardStringContext (
                    builtins.toJSON {
                      inherit (evaluated.systemd) tmpfiles;
                      unit = evaluated.systemd.services.hanko.serviceConfig;
                      renew = evaluated.systemd.services.hanko-renew.serviceConfig;
                      inherit ca;
                      timer = evaluated.systemd.timers.hanko.timerConfig;
                      polkit = evaluated.security.polkit.extraConfig;
                      config = evaluated.environment.etc."hanko/hanko.toml".source.name;
                      caConfig = evaluated.environment.etc."hanko/ca.toml".source.name;
                    }
                  )
                )
              } > $out
            '';

          buf-lint = pkgs.runCommand "hanko-buf-lint" { nativeBuildInputs = [ pkgs.buf ]; } ''
            export HOME=$TMPDIR
            cd ${./proto}
            buf lint
            touch $out
          '';

          proto-generated =
            pkgs.runCommand "hanko-proto-generated"
              {
                nativeBuildInputs = [
                  pkgs.buf
                  pkgs.protoc-gen-go
                  pkgs.protoc-gen-go-grpc
                ];
              }
              ''
                export HOME=$TMPDIR
                cp -r ${./proto} proto
                cp ${./buf.gen.yaml} buf.gen.yaml
                buf generate proto
                diff -r ${./internal/gen} internal/gen
                touch $out
              '';
        }
        // lib.optionalAttrs (lib.hasSuffix "-linux" system) {
          module = moduleConfig { };
          ca-module = (nixosFor system { }).config.environment.etc."hanko/ca.toml".source;
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
          internal = import ./nix/test-internal.nix { inherit self nisshi pkgs; };
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
              pkgs.buf
              pkgs.protoc-gen-go
              pkgs.protoc-gen-go-grpc
            ];
          };
        }
      );

      formatter = forAllSystems (system: (pkgsFor system).nixfmt-tree);
    };
}
