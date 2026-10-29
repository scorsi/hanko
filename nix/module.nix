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
  serviceConfig = import ./hardening.nix // {
    Type = "oneshot";
    ExecStart = "${exe} run /etc/hanko/hanko.toml";
    User = "hanko";
    Group = "hanko";
    StateDirectory = "hanko";
    StateDirectoryMode = "0751";
    # One full run of lock contention, then every order (10m), cleanup (1m) and reload (1m).
    TimeoutStartSec =
      2
      * (
        60
        + 660 * builtins.length cfg.settings.certificates
        + 60 * lib.foldl' (n: c: n + builtins.length (c.reload or [ ])) 0 cfg.settings.certificates
      );
  };
  reloadUnits = lib.unique (lib.concatMap (c: c.reload) (lib.attrValues cfg.certificates));

  # Only the issuer tables some certificate uses: `hanko check` rejects an unused one (ADR 0002).
  uses = issuer: lib.any (c: c.issuer == issuer) (lib.attrValues cfg.certificates);
  generated =
    lib.optionalAttrs (uses "acme") {
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
    }
    // lib.optionalAttrs (uses "internal") {
      internal.ca = cfg.internal.ca;
    }
    // {
      certificates = lib.mapAttrsToList (
        name: c:
        {
          inherit name;
          inherit (c)
            issuer
            reload
            group
            ;
        }
        # Passed whenever set, so `hanko check` reports a key that does not match the issuer.
        // lib.optionalAttrs (c.hosts != [ ]) { inherit (c) hosts; }
        // lib.optionalAttrs (c.spiffeId != null) { spiffe_id = c.spiffeId; }
      ) cfg.certificates;
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

    internal.ca = mkOption {
      type = types.str;
      example = "[fd12:3456:789a::1]:4900";
      description = "hanko-ca's overlay address and port, for `internal` certificates (ADR 0004).";
    };

    certificates = mkOption {
      type = types.attrsOf (
        types.submodule {
          options = {
            issuer = mkOption {
              type = types.enum [
                "acme"
                "internal"
              ];
              default = "acme";
              description = ''
                `acme`: a public certificate, `fullchain.pem` and `key.pem` (ADR 0003). `internal`: an
                X.509-SVID from hanko-ca, `svid.pem`, `key.pem` and `bundle.pem` (ADR 0004).
              '';
            };
            hosts = mkOption {
              type = types.listOf types.str;
              default = [ ];
              example = [ "*.uchi.example.org" ];
              description = "Names an `acme` certificate covers.";
            };
            spiffeId = mkOption {
              type = types.nullOr types.str;
              default = null;
              example = "spiffe://uchi.example.org/vm/api";
              description = "The SPIFFE ID of an `internal` certificate.";
            };
            reload = mkOption {
              type = types.listOf types.str;
              default = [ ];
              example = [ "genkan.service" ];
              description = ''
                Units reloaded after an `acme` certificate changed. An `internal` certificate takes
                none: its consumers watch their files and reload in-process (ADR 0013).
              '';
            };
            group = mkOption {
              type = types.str;
              example = "genkan";
              description = ''
                Group of the certificate's directory (mode 2750, setgid): who may read its files
                under `${state}/<name>/`; for an `internal` certificate, the service's own group (ADR 0005). Included in the file so hanko verifies the directory group.
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
      # A failed boot or switch run (hanko-ca's host or the overlay not up yet) is retried soon
      # rather than at the next timer: 30 s apart, at most five starts an hour, so whatever a run
      # lasts it gives up to the timer after four retries (ADR 0001 amendment). OnFailure= fires
      # only once systemd gives up. Consumers order `after`/`wants` hanko.service, never `requires`.
      # Exit 10 (a validation failure, a CA deadline, a hanko-ca refusal) is not retried: a quick
      # retry would only spend the CA's limits again; the unit fails and OnFailure= fires at once.
      startLimitIntervalSec = 3600;
      startLimitBurst = 5;
      serviceConfig = serviceConfig // {
        RemainAfterExit = true;
        Restart = "on-failure";
        RestartSec = "30s";
        RestartPreventExitStatus = "10";
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
