# NixOS module for hanko (ADR 0001 oneshot and timer, ADR 0002 shape, ADR 0005 identity and
# permissions): the checked file, the user, the directories, the unit, its timer and the polkit
# rule that lets it reload the listed units.
self:
{
  config,
  lib,
  pkgs,
  ...
}:
let
  inherit (lib) mkOption types;
  cfg = config.services.hanko;
  toml = pkgs.formats.toml { };
  exe = lib.getExe cfg.package;
  state = "/var/lib/hanko";
  serviceConfig = {
    Type = "oneshot";
    ExecStart = "${exe} run /etc/hanko/hanko.toml";
    User = "hanko";
    Group = "hanko";
    StateDirectory = "hanko";
    StateDirectoryMode = "0751";
    # Default new files to owner-only; explicit chmod(0640) still permits certificate consumers.
    UMask = "0077";
    LimitCORE = 0; # Private keys must not land in ordinary core files.
    CoredumpFilter = "0x0"; # Exclude memory mappings even when the host pipes dumps to a collector.
    ProtectKernelTunables = true; # No sysctl writes.
    ProtectKernelModules = true; # No module loading or module-tree access.
    ProtectKernelLogs = true; # No kernel log access.
    ProtectControlGroups = true; # No cgroup management.
    ProtectClock = true; # TLS needs clock reads, never clock changes.
    RestrictNamespaces = true; # Neither Go networking nor systemctl creates namespaces.
    RestrictRealtime = true; # No realtime scheduling is needed.
    RestrictSUIDSGID = true; # No set-id files; certificate setgid directories are provisioned outside the unit.
    LockPersonality = true; # Both executables use the native process personality.
    SystemCallArchitectures = "native"; # No foreign-ABI executables.
    # One full run of lock contention, then every order (10m), cleanup (1m) and reload (1m).
    TimeoutStartSec =
      2
      * (
        60
        + 660 * builtins.length cfg.settings.certificates
        + 60 * lib.foldl' (n: c: n + builtins.length (c.reload or [ ])) 0 cfg.settings.certificates
      );
    CapabilityBoundingSet = "";
    NoNewPrivileges = true;
    ProtectSystem = "strict";
    ProtectHome = true;
    PrivateTmp = true;
    PrivateDevices = true;
    RestrictAddressFamilies = [
      "AF_INET"
      "AF_INET6"
      "AF_UNIX"
    ];
  };
  reloadUnits = lib.unique (lib.concatMap (c: c.reload) (lib.attrValues cfg.certificates));

  generated = {
    acme = {
      directory = cfg.acme.directory;
      account_key_file = cfg.acme.accountKeyFile;
      accept_terms = cfg.acme.acceptTerms;
      create_account = cfg.acme.createAccount;
    };
    dns = {
      nameservers = cfg.dns.nameservers;
      tsig_key_file = cfg.dns.tsigKeyFile;
      propagation_timeout = cfg.dns.propagationTimeout;
    };
    certificates = lib.mapAttrsToList (name: c: {
      inherit name;
      inherit (c)
        issuer
        hosts
        reload
        group
        ;
    }) cfg.certificates;
  };

  # `hanko check` at build time: an invalid file never becomes a system (ADR 0002).
  configFile =
    let
      raw = toml.generate "hanko.toml" cfg.settings;
    in
    pkgs.runCommand "hanko.toml" { } ''
      ${exe} check ${raw}
      cp ${raw} $out
    '';
in
{
  options.services.hanko = {
    enable = lib.mkEnableOption "hanko, the homelab certificate service";

    package = mkOption {
      type = types.package;
      default = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
      defaultText = lib.literalExpression "hanko.packages.\${system}.default";
      description = "The hanko package.";
    };

    timer = mkOption {
      type = types.str;
      default = "hourly";
      description = "`OnCalendar=` of the renewal timer; certificate lifetimes must span several periods.";
    };

    onFailure = mkOption {
      type = types.listOf types.str;
      default = [ ];
      example = [ "notify-failure@hanko.service" ];
      description = "Units started when a run fails (`OnFailure=`).";
    };

    acme = {
      directory = mkOption {
        type = types.str;
        example = "https://acme-staging-v02.api.letsencrypt.org/directory";
        description = "ACME directory URL.";
      };
      accountKeyFile = mkOption {
        type = types.str;
        default = "${state}/account.key";
        description = "Where hanko creates its ACME account key (the only secret it creates).";
      };
      acceptTerms = mkOption {
        type = types.bool;
        default = false;
        description = "Accept the CA's terms of service; required to create the account.";
      };
      createAccount = mkOption {
        type = types.bool;
        default = false;
        description = ''
          Let a run create the account key when it is absent, and so a new ACME account. Set it for
          the host's first run only: with it off, an absent key fails the run (`account-key-missing`)
          instead of silently changing the account that CAA `accounturi=` pins (ADR 0008).
        '';
      };
    };

    dns = {
      nameservers = mkOption {
        type = types.listOf types.str;
        example = [ "203.0.113.10:53" ];
        description = "Every public nameserver, by address, as `host:port`.";
      };
      tsigKeyFile = mkOption {
        type = types.str;
        example = "/run/secrets/hanko-tsig";
        description = "File holding `<name>:<base64 secret>`; a sops path, owned by `hanko`, never a value.";
      };
      propagationTimeout = mkOption {
        type = types.str;
        default = "120s";
        description = "How long to wait for a challenge to appear on every nameserver.";
      };
    };

    certificates = mkOption {
      type = types.attrsOf (
        types.submodule {
          options = {
            issuer = mkOption {
              type = types.enum [ "acme" ];
              default = "acme";
              description = "Issuer; `internal` is v1.";
            };
            hosts = mkOption {
              type = types.nonEmptyListOf types.str;
              example = [ "*.uchi.example.org" ];
              description = "Names the certificate covers.";
            };
            reload = mkOption {
              type = types.listOf types.str;
              default = [ ];
              example = [ "genkan.service" ];
              description = "Units reloaded after the certificate changed.";
            };
            group = mkOption {
              type = types.str;
              example = "genkan";
              description = ''
                Group of the certificate's directory (mode 2750, setgid): who may read
                `${state}/<name>/fullchain.pem` and `key.pem`. Included in the file so hanko verifies the directory group.
              '';
            };
          };
        }
      );
      default = { };
      description = "Certificates, by name (lowercase `[a-z0-9-]`, also the directory name).";
    };

    settings = mkOption {
      inherit (toml) type;
      default = { };
      description = ''
        The TOML of ADR 0002. The options above are merged into it; definitions here add to them
        (lists concatenate) and `lib.mkForce` replaces them.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    services.hanko.settings = generated;

    environment.etc."hanko/hanko.toml".source = configFile;

    users.users.hanko = {
      isSystemUser = true;
      group = "hanko";
    };
    users.groups.hanko = { };

    systemd.tmpfiles.rules = [
      "d ${state} 0751 hanko hanko -"
    ]
    ++ lib.mapAttrsToList (name: c: "d ${state}/${name} 2750 hanko ${c.group} -") cfg.certificates;

    systemd.services.hanko = {
      description = "hanko certificate run";
      # Run at boot and by every switch that changes the file, before dependents reload (ADR 0001).
      wantedBy = [ "multi-user.target" ];
      wants = [ "network-online.target" ];
      after = [ "network-online.target" ];
      restartTriggers = [ configFile ];
      inherit (cfg) onFailure;
      serviceConfig = serviceConfig // {
        RemainAfterExit = true;
      };
    };

    # A timer cannot rerun hanko.service, which stays active (RemainAfterExit); it starts this
    # twin instead, same binary and file.
    systemd.services.hanko-renew = {
      description = "hanko certificate run (timer)";
      wants = [ "network-online.target" ];
      after = [ "network-online.target" ];
      inherit (cfg) onFailure;
      inherit serviceConfig;
    };

    systemd.timers.hanko = {
      wantedBy = [ "timers.target" ];
      timerConfig = {
        Unit = "hanko-renew.service";
        OnCalendar = cfg.timer;
        Persistent = true;
        RandomizedDelaySec = "5m";
      };
    };

    # hanko may reload or restart exactly the units listed in its configuration (ADR 0005).
    security.polkit.enable = lib.mkIf (reloadUnits != [ ]) true;
    security.polkit.extraConfig = lib.mkIf (reloadUnits != [ ]) ''
      polkit.addRule(function (action, subject) {
        if (action.id == "org.freedesktop.systemd1.manage-units" && subject.user == "hanko" &&
            ["reload", "restart"].indexOf(action.lookup("verb")) >= 0 &&
            ${builtins.toJSON reloadUnits}.indexOf(action.lookup("unit")) >= 0) {
          return polkit.Result.YES;
        }
      });
    '';
  };
}
