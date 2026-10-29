# M1 nixosTest (ADR 0001, 0003, 0005): Pebble as the CA, two annai `soto` VMs loading the same
# zone with hanko's TSIG key, one host running hanko with a wildcard certificate and a certificate
# for two names, for a dummy consumer with its own user and group. Proves the fan-out (both
# nameservers serve the TXT to hanko's propagation check), the files' group and modes, the reload,
# that a second run and the timer's twin renew nothing, that a concurrent run waits for the lock,
# and that a run renews once a third of Pebble's short certificate validity is left. A second
# consumer ordered After=hanko-node.service proves the boot run skips a unit that is not active yet
# instead of stalling on its queued start job (ADR 0005), and is reloaded by the later renewal.
# Every line both units wrote passes `nisshi validate --logs` (ADR 0007).
{
  self,
  annai,
  nisshi,
  pkgs,
}:
let
  inherit (pkgs) lib;
  validateLogs = nisshi.lib.validateLogs.${pkgs.stdenv.hostPlatform.system};
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
        environment.systemPackages = [
          pkgs.openssl
          pkgs.bind
        ];

        services.hanko-node = {
          enable = true;
          # The test overrides this briefly to prove an actual timer firing.
          timer = "*-12-31 23:59:59";
          acme = {
            directory = "https://${nodes.acme.test-support.acme.caDomain}/dir";
            acceptTerms = true;
            # A fresh VM: the boot run creates the account (ADR 0008).
            createAccount = true;
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
            reload = [
              "consumer.service"
              "late.service"
            ];
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
        specialisation.extra-certificate.configuration.services.hanko-node.certificates.extra = {
          hosts = [ "extra.example.org" ];
          reload = [ "consumer.service" ];
          group = "consumer";
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
          # orders itself After=hanko-node.service, ADR 0001.)
          before = [ "hanko-node.service" ];
          serviceConfig = {
            User = "consumer";
            Group = "consumer";
            RuntimeDirectory = "consumer";
            ExecStart = "${pkgs.coreutils}/bin/sleep infinity";
            ExecReload = "${pkgs.runtimeShell} -c 'echo reloaded >> /run/consumer/reloads'";
          };
        };
        # A consumer ordered as a real one is: its start job waits for hanko's boot run, which
        # must skip it rather than queue a reload behind that job.
        systemd.services.late = {
          wantedBy = [ "multi-user.target" ];
          after = [ "hanko-node.service" ];
          serviceConfig = {
            User = "consumer";
            Group = "consumer";
            RuntimeDirectory = "late";
            ExecStart = "${pkgs.runtimeShell} -c 'touch /run/late/reloads; exec ${pkgs.coreutils}/bin/sleep infinity'";
            ExecReload = "${pkgs.runtimeShell} -c 'echo reloaded >> /run/late/reloads'";
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
      # The binary as the state directory's owner, outside the units (status reads as hanko).
      # hanko-node runs, hanko reports (ADR 0014); both as user hanko (ADR 0011).
      as_node = "runuser -u hanko -- env STATE_DIRECTORY=/var/lib/hanko ${lib.getExe' nodes.hanko.services.hanko-node.package "hanko-node"}"
      as_hanko = "runuser -u hanko -- env STATE_DIRECTORY=/var/lib/hanko ${lib.getExe' nodes.hanko.services.hanko-node.package "hanko"}"

      def journal(unit: str) -> str:
          """hanko's own lines only: `-u` would add PID 1's "Started …", which is not JSON."""
          return f"journalctl --no-pager _SYSTEMD_UNIT={unit} -o cat"

      def journals() -> str:
          return "\n".join(
              m.execute(f"journalctl --no-pager -u {u}")[1]
              for m, u in [(hanko, "hanko-node.service"), (hanko, "hanko-node-renew.service"), (soto1, "annai.service"), (soto2, "annai.service"), (acme, "pebble.service")]
          )

      def fingerprints() -> dict[str, str]:
          return {c: hanko.succeed(f"openssl x509 -noout -fingerprint -sha256 -in /var/lib/hanko/{c}/fullchain.pem") for c in certs}

      def reloads(unit: str = "consumer") -> int:
          return int(hanko.succeed(f"wc -l < /run/{unit}/reloads").strip())

      # Back-to-back failing starts would trip systemd's start rate limit (5 per 10 s), after
      # which a valid restore still fails with start-limit-hit without running hanko.
      start_renew = "systemctl reset-failed hanko-node-renew.service || true; systemctl start hanko-node-renew.service"

      def run_renew() -> str:
          """Starts the timer's twin, waits for it, returns its journal."""
          hanko.succeed(start_renew)
          return hanko.succeed(journal("hanko-node-renew.service"))

      def wait_capture(soto: QemuMachine) -> None:
          """Waits for tcpdump to listen; fails at once, with its status and output, if it died."""
          def listening(last: bool) -> bool:
              if soto.execute("grep -q 'listening on' /tmp/capture")[0] == 0:
                  return True
              dead = soto.execute("systemctl is-active --quiet capture.service")[0] != 0
              if dead or last:
                  print(soto.execute("systemctl status --no-pager capture.service; cat /tmp/capture")[1])
              assert not dead, "capture.service is not active"
              return False
          retry(listening, timeout_seconds=300)

      acme.start()
      soto1.start()
      soto2.start()
      for soto, me in [(soto1, soto1_ip), (soto2, soto2_ip)]:
          soto.wait_for_unit("annai.service")
          soto.wait_for_open_port(53)
          # tcpdump exits at once if eth1 is missing or down: wait for the test VLAN's address.
          soto.wait_until_succeeds(f"ip -4 -br addr show dev eth1 | grep -qwF {me}")
          # Answers sent by this nameserver to hanko only (the VLAN is a shared hub).
          soto.succeed(
              "systemd-run --unit=capture ${pkgs.runtimeShell} -c "
              f"'${pkgs.tcpdump}/bin/tcpdump -i eth1 -n -l -vv src host {me} and src port 53 and dst host {hanko_ip} > /tmp/capture 2>&1'"
          )
          wait_capture(soto)
      acme.wait_for_unit("pebble.service")
      acme.wait_for_open_port(443)

      with subtest("the boot run issues both certificates"):
          # Started only now: its boot run's TXT queries must reach captures already listening.
          hanko.start()
          hanko.wait_until_succeeds("systemctl show -P ActiveState hanko-node.service | grep -qxE 'active|failed'", timeout=600)
          state = hanko.succeed("systemctl show -P ActiveState hanko-node.service").strip()
          assert state == "active", journals()
          for c in certs:
              hanko.succeed(f"test -s /var/lib/hanko/{c}/fullchain.pem -a -s /var/lib/hanko/{c}/key.pem")

      with subtest("the boot run skips the consumer ordered after it, without waiting for it"):
          hanko.wait_for_unit("late.service")
          start, end = (int(hanko.succeed(f"systemctl show -P {p} hanko-node.service")) for p in ["ExecMainStartTimestampMonotonic", "ExecMainExitTimestampMonotonic"])
          print(f"hanko-node.service boot run: {(end - start) / 1e6:.1f} s")
          # The order timeout a stalled reload would hit is 600 s; issuing both certificates takes far less.
          assert 0 < end - start < 300_000_000, journals()
          out = hanko.succeed(journal("hanko-node.service"))
          print(out)
          assert '"event":"reload-skipped","certificate":"home","unit":"late.service"' in out, out
          assert '"event":"reload-failed"' not in out, out
          assert '"event":"run-completed","certificates":2,"renewed":2,"failed":0,' in out, out
          assert reloads("late") == 0, hanko.succeed("cat /run/late/reloads; systemctl status late.service")
          late_pid = hanko.succeed("systemctl show -P MainPID late.service")

      with subtest("both nameservers served every challenge record to hanko"):
          for soto in [soto1, soto2]:
              soto.succeed("systemctl stop capture.service")
              out = soto.succeed("cat /tmp/capture")
              for names in certs.values():
                  for name in names:
                      assert re.search(rf"TXT\? {re.escape(name)} .*TXT \"", out), out
          out = soto1.succeed("journalctl --no-pager -u annai.service") + soto2.succeed("journalctl --no-pager -u annai.service")
          assert '"event":"update-refused"' not in out, out

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
          hanko.fail("runuser -u consumer -- cat /var/lib/hanko/account.key")
          hanko.fail("runuser -u nobody -- cat /var/lib/hanko/account.key")

      with subtest("the listed unit was reloaded once per certificate"):
          assert reloads() == 2, hanko.succeed("cat /run/consumer/reloads; systemctl status consumer.service")
          first_pid = hanko.succeed("systemctl show -P MainPID consumer.service")

      # Everything up to the renewal must happen while more than a third of the validity is left.
      before = fingerprints()
      for c in certs:
          hanko.succeed(f"openssl x509 -noout -checkend {third + 5} -in /var/lib/hanko/{c}/fullchain.pem")

      with subtest("a second run renews nothing"):
          hanko.succeed("systemctl restart hanko-node.service")
          assert fingerprints() == before and reloads() == 2 and reloads("late") == 0, journals()

      with subtest("a real timer tick runs the twin and renews nothing"):
          hanko.succeed(
              "mkdir -p /run/systemd/system/hanko-node.timer.d",
              "printf '[Timer]\nOnActiveSec=1s\nRandomizedDelaySec=0\nAccuracySec=1us\n' > /run/systemd/system/hanko-node.timer.d/test.conf",
              "systemctl daemon-reload",
              "systemctl restart hanko-node.timer",
          )
          hanko.wait_until_succeeds(journal("hanko-node-renew.service") + " | grep -q run-completed", timeout=30)
          hanko.wait_until_succeeds("systemctl show -P ActiveState hanko-node-renew.service | grep -qx inactive", timeout=30)
          hanko.succeed("systemctl stop hanko-node.timer; rm /run/systemd/system/hanko-node.timer.d/test.conf; systemctl daemon-reload")
          out = hanko.succeed(journal("hanko-node-renew.service"))
          assert out.count('"event":"certificate-valid"') == 2 and '"event":"certificate-renewing"' not in out, out
          assert fingerprints() == before and reloads() == 2 and reloads("late") == 0, journals()

      with subtest("a concurrent run waits for the lock, then renews nothing"):
          hanko.succeed("systemd-run --unit=holder ${pkgs.util-linux}/bin/flock /var/lib/hanko/.lock ${pkgs.coreutils}/bin/sleep 8")
          hanko.wait_until_succeeds("systemctl is-active holder.service")
          hanko.sleep(1)
          hanko.succeed("systemctl start --no-block hanko-node-renew.service")
          hanko.sleep(3)
          out = hanko.succeed("systemctl show -P ActiveState hanko-node-renew.service")
          assert out.strip() == "activating", out
          hanko.wait_until_succeeds("systemctl show -P ActiveState hanko-node-renew.service | grep -qx inactive", timeout=30)
          out = hanko.succeed("systemctl show -P Result hanko-node-renew.service; " + journal("hanko-node-renew.service"))
          assert out.startswith("success") and out.count('"event":"certificate-valid"') == 4 and '"event":"certificate-renewing"' not in out, out
          assert fingerprints() == before and reloads() == 2 and reloads("late") == 0, journals()
          for c in certs:
              hanko.succeed(f"openssl x509 -noout -checkend {third + 5} -in /var/lib/hanko/{c}/fullchain.pem")

      with subtest("a run renews both certificates once a third of their lifetime is left"):
          for c in certs:
              hanko.wait_until_succeeds(f"! openssl x509 -noout -checkend {third - 5} -in /var/lib/hanko/{c}/fullchain.pem", timeout=300)
          # M3: with both due, a broken TSIG key fails the run, and `hanko status` still shows
          # both certificates valid, with the failure (ADR 0011).
          hanko.succeed(
              "printf 'hanko:not base64\\n' > /run/hanko-tsig-broken",
              "sed -E 's|^tsig_key_file *=.*|tsig_key_file = \"/run/hanko-tsig-broken\"|' /etc/hanko/hanko.toml > /run/hanko-broken.toml",
              "grep -qx 'tsig_key_file = \"/run/hanko-tsig-broken\"' /run/hanko-broken.toml",
          )
          code, out = hanko.execute(f"{as_node} run /run/hanko-broken.toml 2>&1")
          assert code != 0 and out.count('"event":"certificate-failed"') == 2 and '"err":"tsig key /run/hanko-tsig-broken: ' in out, out
          code, out = hanko.execute(f"{as_hanko} status /etc/hanko/hanko.toml")
          assert code == 0, out
          for c in certs:
              assert re.search(r'"level":"warn","v":1,"event":"certificate-status","certificate":"' + c + r'","issuer":"acme",.*"valid":true,"last_run":"[^"]+","last_result":"failed","err":"tsig key ', out), out
          hanko.succeed(f"{as_hanko} status /etc/hanko/hanko.toml | ${validateLogs} validate --logs")
          out = run_renew()
          assert out.count('"event":"certificate-renewing"') == 2 and '"reason":"less than a third of its lifetime left"' in out, out
          assert '"event":"run-completed","certificates":2,"renewed":2,"failed":0,' in out, out
          after = fingerprints()
          assert all(after[c] != before[c] for c in certs), journals()
          assert reloads() == 4, hanko.succeed("cat /run/consumer/reloads")
          # Active by now, so the renewal reloads it (home only), without a restart.
          assert reloads("late") == 1, hanko.succeed("cat /run/late/reloads; systemctl status late.service") + journals()
          assert hanko.succeed("systemctl show -P MainPID late.service") == late_pid, journals()
          assert hanko.succeed("systemctl show -P MainPID consumer.service") == first_pid, journals()
          for c in certs:
              out = hanko.succeed(f"stat -c '%a %U %G' /var/lib/hanko/{c}/fullchain.pem /var/lib/hanko/{c}/key.pem")
              assert out == "640 hanko consumer\n640 hanko consumer\n", out
              hanko.succeed(f"openssl x509 -noout -checkend {third + 5} -in /var/lib/hanko/{c}/fullchain.pem")
          out = hanko.succeed(f"{as_hanko} status /etc/hanko/hanko.toml")
          assert out.count('"level":"info","v":1,"event":"certificate-status"') == 2 and out.count('"valid":true,"last_run":') == 2 and out.count('"last_result":"ok"') == 2, out

      def invocation(unit: str) -> str:
          """The lines of the unit's last run only."""
          inv = hanko.succeed(f"systemctl show -P InvocationID {unit}").strip()
          return hanko.succeed(f"journalctl --no-pager _SYSTEMD_INVOCATION_ID={inv} -o cat")

      with subtest("a missing certificate directory fails before any order (review H5)"):
          hanko.succeed("mv /var/lib/hanko/cv /var/lib/hanko-cv-aside")
          hanko.fail(start_renew)
          out = invocation("hanko-node-renew.service")
          assert '"event":"certificate-failed","certificate":"cv","err":"directory: ' in out, out
          # The CA is contacted only by an order: no account line, no order.
          assert '"event":"acme-account"' not in out and '"event":"certificate-written"' not in out, out
          assert '"event":"run-completed","certificates":2,"renewed":0,"failed":1,' in out, out
          hanko.succeed("mv /var/lib/hanko-cv-aside /var/lib/hanko/cv")

      with subtest("a missing account key is refused, never recreated, without create_account (review H4)"):
          hanko.succeed(
              "mv /var/lib/hanko/account.key /var/lib/hanko-account.key.aside",
              "mv /var/lib/hanko/cv/fullchain.pem /var/lib/hanko-cv.pem.aside",
              "sed -E 's/create_account *= *true/create_account = false/' /etc/hanko/hanko.toml > /run/hanko-strict.toml",
              "grep -qx 'create_account = false' /run/hanko-strict.toml",
          )
          code, out = hanko.execute(
              "runuser -u hanko -- env STATE_DIRECTORY=/var/lib/hanko ${lib.getExe' nodes.hanko.services.hanko-node.package "hanko-node"} run /run/hanko-strict.toml 2>&1"
          )
          print(out)
          assert code != 0 and '"event":"account-key-missing"' in out and '"event":"acme-account"' not in out, out
          hanko.fail("test -e /var/lib/hanko/account.key")
          hanko.succeed(
              "mv /var/lib/hanko-account.key.aside /var/lib/hanko/account.key",
              "mv /var/lib/hanko-cv.pem.aside /var/lib/hanko/cv/fullchain.pem",
          )
          run_renew()
          out = invocation("hanko-node-renew.service")
          assert '"event":"certificate-renewing"' not in out and '"failed":0' in out, out

      with subtest("both units keep key and process protections (review H14)"):
          for unit in ["hanko-node.service", "hanko-node-renew.service"]:
              for prop in ["ProtectKernelTunables", "ProtectKernelModules", "ProtectKernelLogs", "ProtectControlGroups", "ProtectClock", "RestrictRealtime", "RestrictSUIDSGID", "LockPersonality"]:
                  assert hanko.succeed(f"systemctl show -P {prop} {unit}").strip() == "yes", prop
              assert hanko.succeed(f"systemctl show -P UMask {unit}").strip() == "0077"
              assert hanko.succeed(f"systemctl show -P LimitCORE {unit}").strip() == "0"
              assert int(hanko.succeed(f"systemctl show -P CoredumpFilter {unit}").strip(), 0) == 0
              assert hanko.succeed(f"systemctl show -P RestrictNamespaces {unit}").strip() == "yes"
              assert hanko.succeed(f"systemctl show -P SystemCallArchitectures {unit}").strip() == "native"
              assert hanko.succeed(f"systemctl show -P TimeoutStartUSec {unit}").strip() != "infinity"

      with subtest("failed reload is retried without an order or restart (review H7/H8)"):
          current = fingerprints()
          pid = hanko.succeed("systemctl show -P MainPID consumer.service")
          hanko.succeed(
              "mkdir -p /run/systemd/system/consumer.service.d",
              "printf '[Service]\nExecReload=\nExecReload=${pkgs.coreutils}/bin/false\n' > /run/systemd/system/consumer.service.d/test.conf",
              "systemctl daemon-reload",
              "runuser -u hanko -- sh -c 'umask 077; echo pending > /var/lib/hanko/home/.reload-pending'",
          )
          hanko.fail(start_renew)
          out = invocation("hanko-node-renew.service")
          assert '"event":"reload-failed"' in out and '"renewed":0,"failed":1' in out, out
          assert '"event":"acme-account"' not in out, out
          assert hanko.succeed("systemctl show -P MainPID consumer.service") == pid
          hanko.succeed("test -f /var/lib/hanko/home/.reload-pending")
          hanko.succeed("rm /run/systemd/system/consumer.service.d/test.conf; systemctl daemon-reload")
          run_renew()
          assert fingerprints() == current
          hanko.fail("test -e /var/lib/hanko/home/.reload-pending")

      with subtest("mounted-over or misprovisioned directory fails before ordering (review H6)"):
          hanko.succeed("mkdir -p /run/empty-cert; mount --bind /run/empty-cert /var/lib/hanko/cv")
          try:
              hanko.fail(start_renew)
              out = invocation("hanko-node-renew.service")
              assert '"event":"certificate-failed","certificate":"cv"' in out, out
              assert '"event":"acme-account"' not in out, out
          finally:
              hanko.succeed("umount /var/lib/hanko/cv")
          # GNU chmod keeps a directory's setgid bit on a numeric mode like 0750: clear it
          # symbolically and prove it is gone, or the run legitimately succeeds.
          for bad, restore in [("chmod g-s /var/lib/hanko/cv; test ! -g /var/lib/hanko/cv", "chmod 2750 /var/lib/hanko/cv"), ("chmod 2770 /var/lib/hanko/cv", "chmod 2750 /var/lib/hanko/cv"), ("chgrp hanko /var/lib/hanko/cv", "chgrp consumer /var/lib/hanko/cv; chmod 2750 /var/lib/hanko/cv")]:
              hanko.succeed(bad)
              hanko.fail(start_renew)
              out = invocation("hanko-node-renew.service")
              assert '"event":"certificate-failed","certificate":"cv"' in out, out
              assert '"event":"acme-account"' not in out, out
              hanko.succeed(restore)
          run_renew()

      with subtest("second authority failure aborts and cleans the first authority (review H10/H13)"):
          hanko.succeed("mv /var/lib/hanko/cv/fullchain.pem /run/cv-chain.aside")
          soto2.succeed("systemctl stop annai.service")
          try:
              hanko.fail(start_renew)
              out = invocation("hanko-node-renew.service")
              assert '"event":"certificate-failed","certificate":"cv"' in out, out
              assert '"event":"certificate-written","certificate":"cv"' not in out, out
              for name in certs["cv"]:
                  assert hanko.succeed(f"dig +short @{soto1_ip} TXT {name}").strip() == ""
          finally:
              soto2.succeed("systemctl start annai.service")
              hanko.succeed("mv /run/cv-chain.aside /var/lib/hanko/cv/fullchain.pem")
          run_renew()

      with subtest("a configuration-changing switch provisions and issues a new certificate"):
          hanko.succeed("/run/current-system/specialisation/extra-certificate/bin/switch-to-configuration switch")
          hanko.succeed("test -s /var/lib/hanko/extra/key.pem; openssl x509 -noout -checkend 0 -in /var/lib/hanko/extra/fullchain.pem")
          out = invocation("hanko-node.service")
          assert '"event":"certificate-written","certificate":"extra"' in out, out

      with subtest("every line hanko wrote passes the log schema (ADR 0007)"):
          # Empty input passes the validator: first prove the events are there.
          for unit, events in [
              ("hanko-node.service", ["acme-account-register", "acme-account", "certificate-renewing", "certificate-written", "reload-skipped", "certificate-valid", "run-completed"]),
              ("hanko-node-renew.service", ["acme-account", "certificate-valid", "certificate-renewing", "certificate-written", "run-completed"]),
          ]:
              out = hanko.succeed(journal(unit))
              for e in events:
                  assert f'"event":"{e}"' in out, out
              # The account URL, for CAA accounturi= (RFC 8657): on the run that registers and on later ones.
              assert re.search(r'"event":"acme-account","directory":"https://[^"]+","uri":"https://[^"]+"', out), out
              assert re.search(r'"event":"certificate-written","certificate":"home","not_after":"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{9}Z"', out), out
              hanko.succeed(f"{journal(unit)} | ${validateLogs} validate --logs")
    '';
}
