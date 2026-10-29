# NixOS module for hanko-ca, the internal signer (ADR 0004 file and daemon, ADR 0005 user and
# hardening): the checked file, the static user and the hardened unit. It persists nothing but
# its log.
self:
{
  config,
  lib,
  pkgs,
  ...
}:
let
  inherit (lib) mkOption types;
  cfg = config.services.hanko-ca;
  exe = lib.getExe cfg.package;

  raw = (pkgs.formats.toml { }).generate "ca.toml" {
    ca = {
      key_file = cfg.keyFile;
      cert_file = cfg.certFile;
      inherit (cfg) listen;
      svid_lifetime = cfg.svidLifetime;
    };
    hosts = lib.mapAttrsToList (address: ids: { inherit address ids; }) cfg.hosts;
  };
  # `hanko-ca check` at build time: an invalid file never becomes a system (ADR 0002).
  configFile = pkgs.runCommand "ca.toml" { } ''
    ${exe} check ${raw}
    cp ${raw} $out
  '';
in
{
  options.services.hanko-ca = {
    enable = lib.mkEnableOption "hanko-ca, the internal signer of service identities";

    package = mkOption {
      type = types.package;
      default = self.packages.${pkgs.stdenv.hostPlatform.system}.hanko-ca;
      defaultText = lib.literalExpression "hanko.packages.\${system}.hanko-ca";
      description = "The hanko-ca package.";
    };

    keyFile = mkOption {
      type = types.str;
      example = "/run/secrets/hanko-ca-key";
      description = "The CA private key (ECDSA P-256, PEM); a sops path owned by `hanko-ca`, mode 0400.";
    };

    certFile = mkOption {
      type = types.str;
      example = "/etc/hanko/ca.pem";
      description = "The CA certificate(s), PEM: the one matching the key signs, all form the bundle.";
    };

    listen = mkOption {
      type = types.str;
      example = "[fd12:3456:789a::1]:4900";
      description = "The node's overlay address and a port above 1024.";
    };

    svidLifetime = mkOption {
      type = types.str;
      default = "24h";
      description = "Lifetime of every X.509-SVID.";
    };

    hosts = mkOption {
      type = types.attrsOf (types.nonEmptyListOf types.str);
      default = { };
      example = {
        "fd12:3456:789a::2" = [ "spiffe://uchi.example.org/vm/api" ];
      };
      description = "Overlay address of each hanko host and the SPIFFE IDs it may request.";
    };
  };

  config = lib.mkIf cfg.enable {
    environment.etc."hanko/ca.toml".source = configFile;

    users.users.hanko-ca = {
      isSystemUser = true;
      group = "hanko-ca";
    };
    users.groups.hanko-ca = { };

    systemd.services.hanko-ca = {
      description = "hanko-ca internal signer";
      wantedBy = [ "multi-user.target" ];
      wants = [ "network-online.target" ];
      after = [ "network-online.target" ];
      restartTriggers = [ configFile ];
      serviceConfig = import ./hardening.nix // {
        ExecStart = "${exe} serve /etc/hanko/ca.toml";
        User = "hanko-ca";
        Group = "hanko-ca";
        # The overlay address may appear after network-online; binding fails until it does.
        Restart = "on-failure";
        RestartSec = 5;
      };
    };
  };
}
