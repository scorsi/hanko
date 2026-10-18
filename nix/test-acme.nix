# M1 nixosTest (ADR 0001, 0003, 0005): Pebble as the CA, two annai `soto` VMs loading the same
# zone with hanko's TSIG key, one host running hanko with a wildcard certificate and a certificate
# for two names, for a dummy consumer with its own user and group. Proves the fan-out (both
# nameservers serve the TXT to hanko's propagation check), the files' group and modes, the reload,
# that a second run and the timer's twin renew nothing, that a concurrent run waits for the lock,
# and that a run renews once a third of Pebble's short certificate validity is left.
{
  self,
  annai,
  pkgs,
}:
let
  inherit (pkgs) lib;
  secret = "c2VjcmV0LXNlY3JldC1zZWNyZXQtc2VjcmV0LXNlY3JldC0xMjM0";
  # One key file in hanko's `<name>:<base64>` format, read by both products (annai accepts it).
  tsigKey = pkgs.writeText "hanko-tsig" "hanko:${secret}\n";
  # Pebble 2.6.0's `certificateValidityPeriod`, in seconds (cmd/pebble/main.go, ca/ca.go); the
  # default is five years. A run renews when less than a third is left: after 160 s here.
  validity = 240;

  acmeServer = "${pkgs.path}/nixos/tests/common/acme/server";
  testCerts = import "${acmeServer}/snakeoil-certs.nix";
  pebbleConf = pkgs.writeText "pebble.json" (
    builtins.toJSON {
      pebble = {
        listenAddress = "0.0.0.0:443";
        managementListenAddress = "0.0.0.0:15000";
        certificate = testCerts.${testCerts.domain}.cert;
        privateKey = testCerts.${testCerts.domain}.key;
        httpPort = 80;
        tlsPort = 443;
        certificateValidityPeriod = validity;
      };
    }
  );

  soto =
    { nodes, ... }:
    {
      imports = [ annai.nixosModules.default ];
      services.annai = {
        enable = true;
        mode = "soto";
        update.keys.hanko.secretFile = "/etc/annai/hanko.key";
        zones."example.org." = {
          ttl = 300;
          serial = 1760400000;
          soa = {
            mname = "ns1.example.org.";
            rname = "hostmaster.example.org.";
            refresh = 3600;
            retry = 600;
            expire = 604800;
            minimum = 300;
          };
          names = {
            "@".ns = [
              "ns1"
              "ns2"
            ];
            ns1.a = [ nodes.soto1.networking.primaryIPAddress ];
            ns2.a = [ nodes.soto2.networking.primaryIPAddress ];
          };
        };
      };
      # Root-only, as the sops secret is; annai reads it through LoadCredential.
      environment.etc."annai/hanko.key" = {
        source = tsigKey;
        mode = "0400";
      };
      environment.systemPackages = [ pkgs.tcpdump ];
      networking.firewall.allowedUDPPorts = [ 53 ];
      networking.firewall.allowedTCPPorts = [ 53 ];
    };
in
pkgs.testers.runNixOSTest {
  name = "hanko-acme";

  nodes = {
    acme =
      { nodes, ... }:
      {
        imports = [ acmeServer ];
        systemd.services.pebble = {
          # Fresh authorizations on every order, so a renewal goes through DNS-01 again.
          environment.PEBBLE_AUTHZREUSE = "0";
          # annai's soto never forwards: Pebble asks soto1 directly for the challenge records.
          serviceConfig.ExecStart = lib.mkForce "${lib.getExe pkgs.pebble} -config ${pebbleConf} -dnsserver ${nodes.soto1.networking.primaryIPAddress}:53";
        };
      };

    soto1 = soto;
    soto2 = soto;

    hanko =
      { nodes, ... }:
      {
        imports = [ self.nixosModules.default ];
        security.pki.certificateFiles = [ nodes.acme.test-support.acme.caCert ];
        environment.systemPackages = [ pkgs.openssl ];

        services.hanko = {
          enable = true;
          # Never elapses during the test: the twin is started by hand.
          timer = "*-12-31 23:59:59";
          acme = {
            directory = "https://${nodes.acme.test-support.acme.caDomain}/dir";
            acceptTerms = true;
          };
          dns = {
            nameservers = [
              "${nodes.soto1.networking.primaryIPAddress}:53"
              "${nodes.soto2.networking.primaryIPAddress}:53"
            ];
            tsigKeyFile = "/etc/hanko/tsig";
          };
          certificates.home = {
            hosts = [
              "*.uchi.example.org"
              "uchi.example.org"
            ];
            reload = [ "consumer.service" ];
            group = "consumer";
          };
          certificates.cv = {
            hosts = [
              "cv.example.org"
              "cv.soto.example.org"
            ];
            reload = [ "consumer.service" ];
            group = "consumer";
          };
        };
        environment.etc."hanko/tsig" = {
          source = tsigKey;
          mode = "0400";
          user = "hanko";
        };

        # The consumer: its own static user and group (ADR 0005), a reload that leaves a trace.
        users.users.consumer = {
          isSystemUser = true;
          group = "consumer";
        };
        users.groups.consumer = { };
        systemd.services.consumer = {
          wantedBy = [ "multi-user.target" ];
          # Active before hanko's boot run reloads it; it reads no file at start. (A real consumer
          # orders itself After=hanko.service, ADR 0001.)
          before = [ "hanko.service" ];
          serviceConfig = {
            User = "consumer";
            Group = "consumer";
            RuntimeDirectory = "consumer";
            ExecStart = "${pkgs.coreutils}/bin/sleep infinity";
            ExecReload = "${pkgs.runtimeShell} -c 'echo reloaded >> /run/consumer/reloads'";
          };
        };
      };
  };

  testScript =
    { nodes, ... }:
    ''
      import re

      soto1_ip = "${nodes.soto1.networking.primaryIPAddress}"
      soto2_ip = "${nodes.soto2.networking.primaryIPAddress}"
      hanko_ip = "${nodes.hanko.networking.primaryIPAddress}"
      certs = {
          "home": ["_acme-challenge.uchi.example.org."],
          "cv": ["_acme-challenge.cv.example.org.", "_acme-challenge.cv.soto.example.org."],
      }
      third = ${toString validity} // 3

      def journals() -> str:
          return "\n".join(
              m.execute(f"journalctl --no-pager -u {u}")[1]
              for m, u in [(hanko, "hanko.service"), (hanko, "hanko-renew.service"), (soto1, "annai.service"), (soto2, "annai.service"), (acme, "pebble.service")]
          )

      def fingerprints() -> dict[str, str]:
          return {c: hanko.succeed(f"openssl x509 -noout -fingerprint -sha256 -in /var/lib/hanko/{c}/fullchain.pem") for c in certs}

      def reloads() -> int:
          return int(hanko.succeed("wc -l < /run/consumer/reloads").strip())

      def run_renew() -> str:
          """Starts the timer's twin, waits for it, returns its journal."""
          hanko.succeed("systemctl start hanko-renew.service")
          return hanko.succeed("journalctl --no-pager -u hanko-renew.service")

      acme.start()
      soto1.start()
      soto2.start()
      for soto, me in [(soto1, soto1_ip), (soto2, soto2_ip)]:
          soto.wait_for_unit("annai.service")
          soto.wait_for_open_port(53)
          # Answers sent by this nameserver to hanko only (the VLAN is a shared hub).
          soto.succeed(
              "systemd-run --unit=capture ${pkgs.runtimeShell} -c "
              f"'${pkgs.tcpdump}/bin/tcpdump -i eth1 -n -l -vv src host {me} and src port 53 and dst host {hanko_ip} > /tmp/capture 2>&1'"
          )
          soto.wait_until_succeeds("grep -q 'listening on' /tmp/capture")
      acme.wait_for_unit("pebble.service")
      acme.wait_for_open_port(443)

      with subtest("the boot run issues both certificates"):
          hanko.start()
          hanko.wait_until_succeeds("systemctl show -P ActiveState hanko.service | grep -qxE 'active|failed'", timeout=600)
          state = hanko.succeed("systemctl show -P ActiveState hanko.service").strip()
          assert state == "active", journals()
          for c in certs:
              hanko.succeed(f"test -s /var/lib/hanko/{c}/fullchain.pem -a -s /var/lib/hanko/{c}/key.pem")

      with subtest("both nameservers served every challenge record to hanko"):
          for soto in [soto1, soto2]:
              soto.succeed("systemctl stop capture.service")
              out = soto.succeed("cat /tmp/capture")
              for names in certs.values():
                  for name in names:
                      assert re.search(rf"TXT\? {re.escape(name)} .*TXT \"", out), out
          out = soto1.succeed("journalctl --no-pager -u annai.service") + soto2.succeed("journalctl --no-pager -u annai.service")
          assert "event=update-refused" not in out, out

      with subtest("the certificates cover their names and match their keys"):
          for c, sans in [("home", ["DNS:*.uchi.example.org", "DNS:uchi.example.org"]), ("cv", ["DNS:cv.example.org", "DNS:cv.soto.example.org"])]:
              out = hanko.succeed(f"openssl x509 -noout -issuer -ext subjectAltName -in /var/lib/hanko/{c}/fullchain.pem")
              assert "Pebble" in out and all(s in out for s in sans), out
              cert_pub = hanko.succeed(f"openssl x509 -noout -pubkey -in /var/lib/hanko/{c}/fullchain.pem")
              key_pub = hanko.succeed(f"openssl pkey -pubout -in /var/lib/hanko/{c}/key.pem")
              assert cert_pub == key_pub, cert_pub + key_pub

      with subtest("group and modes (ADR 0005): the consumer reads its key, nobody else does"):
          out = hanko.succeed("stat -c '%a %U %G' /var/lib/hanko /var/lib/hanko/account.key")
          assert out == "751 hanko hanko\n600 hanko hanko\n", out
          for c in certs:
              out = hanko.succeed(f"stat -c '%a %U %G' /var/lib/hanko/{c} /var/lib/hanko/{c}/fullchain.pem /var/lib/hanko/{c}/key.pem")
              assert out == "2750 hanko consumer\n640 hanko consumer\n640 hanko consumer\n", out
              hanko.succeed(f"runuser -u consumer -- cat /var/lib/hanko/{c}/key.pem /var/lib/hanko/{c}/fullchain.pem")
              hanko.fail(f"runuser -u nobody -- cat /var/lib/hanko/{c}/key.pem")
          hanko.fail("runuser -u consumer -- ls /var/lib/hanko")

      with subtest("the listed unit was reloaded once per certificate"):
          assert reloads() == 2, hanko.succeed("cat /run/consumer/reloads; systemctl status consumer.service")
          first_pid = hanko.succeed("systemctl show -P MainPID consumer.service")

      # Everything up to the renewal must happen while more than a third of the validity is left.
      before = fingerprints()
      for c in certs:
          hanko.succeed(f"openssl x509 -noout -checkend {third + 5} -in /var/lib/hanko/{c}/fullchain.pem")

      with subtest("a second run renews nothing"):
          hanko.succeed("systemctl restart hanko.service")
          assert fingerprints() == before and reloads() == 2, journals()

      with subtest("the timer's twin runs and renews nothing"):
          out = run_renew()
          assert out.count("certificate valid") == 2 and "renewing" not in out, out
          assert fingerprints() == before and reloads() == 2, journals()

      with subtest("a concurrent run waits for the lock, then renews nothing"):
          hanko.succeed("systemd-run --unit=holder ${pkgs.util-linux}/bin/flock /var/lib/hanko/.lock ${pkgs.coreutils}/bin/sleep 8")
          hanko.wait_until_succeeds("systemctl is-active holder.service")
          hanko.sleep(1)
          hanko.succeed("systemctl start --no-block hanko-renew.service")
          hanko.sleep(3)
          out = hanko.succeed("systemctl show -P ActiveState hanko-renew.service")
          assert out.strip() == "activating", out
          hanko.wait_until_succeeds("systemctl show -P ActiveState hanko-renew.service | grep -qx inactive", timeout=30)
          out = hanko.succeed("systemctl show -P Result hanko-renew.service; journalctl --no-pager -u hanko-renew.service")
          assert out.startswith("success") and out.count("certificate valid") == 4 and "renewing" not in out, out
          assert fingerprints() == before and reloads() == 2, journals()
          for c in certs:
              hanko.succeed(f"openssl x509 -noout -checkend {third + 5} -in /var/lib/hanko/{c}/fullchain.pem")

      with subtest("a run renews both certificates once a third of their lifetime is left"):
          for c in certs:
              hanko.wait_until_succeeds(f"! openssl x509 -noout -checkend {third - 5} -in /var/lib/hanko/{c}/fullchain.pem", timeout=300)
          out = run_renew()
          assert out.count("renewing") == 2 and "less than a third" in out, out
          after = fingerprints()
          assert all(after[c] != before[c] for c in certs), journals()
          assert reloads() == 4, hanko.succeed("cat /run/consumer/reloads")
          assert hanko.succeed("systemctl show -P MainPID consumer.service") == first_pid, journals()
          for c in certs:
              out = hanko.succeed(f"stat -c '%a %U %G' /var/lib/hanko/{c}/fullchain.pem /var/lib/hanko/{c}/key.pem")
              assert out == "640 hanko consumer\n640 hanko consumer\n", out
              hanko.succeed(f"openssl x509 -noout -checkend {third + 5} -in /var/lib/hanko/{c}/fullchain.pem")
    '';
}
