# Sample configuration for the module checks in flake.nix: the examples of ADR 0002 (hanko-node) and
# ADR 0004 (hanko-ca), in module form.
{
  system.stateVersion = "26.05";

  services.hanko-node = {
    enable = true;
    acme = {
      directory = "https://acme-staging-v02.api.letsencrypt.org/directory";
      acceptTerms = true;
    };
    dns = {
      nameservers = [
        "203.0.113.10:53"
        "[2001:db8::10]:53"
      ];
      tsigKeyFile = "/run/secrets/hanko-tsig";
    };
    certificates.home = {
      hosts = [
        "*.uchi.example.org"
        "uchi.example.org"
      ];
      reload = [ "genkan.service" ];
      group = "genkan";
    };
    certificates.cv = {
      hosts = [ "cv.example.org" ];
      reload = [ "genkan.service" ];
      group = "genkan";
    };
    internal.ca = "[fd12:3456:789a::1]:4900";
    internal.renewFraction = 0.25;
    certificates.api = {
      issuer = "internal";
      spiffeId = "spiffe://uchi.example.org/vm/api";
      group = "api";
    };
  };

  services.hanko-ca = {
    enable = true;
    keyFile = "/run/secrets/hanko-ca-key";
    certFile = "/etc/hanko/ca.pem";
    listen = "[fd12:3456:789a::1]:4900";
    hosts."fd12:3456:789a::2" = [
      "spiffe://uchi.example.org/vm/api"
      "spiffe://uchi.example.org/vm/git"
    ];
  };

  users.groups.genkan = { };
  users.groups.api = { };
}
