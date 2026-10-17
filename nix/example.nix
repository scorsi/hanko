# Sample configuration for the module checks in flake.nix: the example of ADR 0002, in module form.
{
  system.stateVersion = "26.05";

  services.hanko = {
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
  };

  users.groups.genkan = { };
}
