# v1 nixosTest (ADR 0004, 0005, 0012): hanko-ca on `ca`, hanko on `alpha` and `beta`, each with
# a service `svc` holding an X.509-SVID for `spiffe://uchi.example.org/<host>/svc`. The services
# authenticate each other by SPIFFE ID over mutual TLS; an ID not allowed for the caller's address
# is refused; a run with nothing due still refreshes the bundle (rotation step (a) of ADR 0012 adds
# a second CA); the timer renews both SVIDs and both services serve the new ones, read from their
# files, with neither a reload nor a restart from hanko (ADR 0013). Every line of hanko and hanko-ca passes `nisshi validate --logs` (ADR 0007).
#
# The overlay is the test's VM network: kekkai is not a dependency of hanko's test. A host's
# address on it stands for its kekkai overlay address, the attested source address hanko-ca
# authorises on (ADR 0004); nothing in the test spoofs it.
{
  self,
  nisshi,
  pkgs,
}:
let
  inherit (pkgs) lib;
  validateLogs = nisshi.lib.validateLogs.${pkgs.stdenv.hostPlatform.system};
  python = pkgs.python3.interpreter;
  svc = ./test-svc.py;
  id = host: "spiffe://uchi.example.org/${host}/svc";
  # Renewed when less than half is left: 16 min, NotBefore one minute back, so an SVID is due
  # seven minutes after issuance, which leaves the subtests before the timer's time to run.
  lifetime = "16m";

  # The CA and the next one of a rotation (ADR 0012); in production the key comes from sops.
  caMaterial = pkgs.runCommand "hanko-test-ca" { nativeBuildInputs = [ pkgs.openssl ]; } ''
    mkdir $out
    cat > ext.cnf <<EOF
    [req]
    distinguished_name = dn
    x509_extensions = v3
    [dn]
    [v3]
    basicConstraints = critical,CA:TRUE
    keyUsage = critical,keyCertSign
    subjectKeyIdentifier = hash
    EOF
    for n in ca next; do
      openssl ecparam -name prime256v1 -genkey -noout -out $out/$n.key
      openssl req -x509 -new -config ext.cnf -key $out/$n.key -subj /CN=hanko-test-$n -days 3650 -out $out/$n.pem
    done
  '';

  host =
    name: peer:
    { nodes, ... }:
    {
      imports = [ self.nixosModules.default ];
      environment.systemPackages = [ pkgs.openssl ];
      services.hanko-node = {
        enable = true;
        timer = "minutely";
        internal.ca = "${nodes.ca.networking.primaryIPAddress}:4900";
        certificates.svc = {
          issuer = "internal";
          spiffeId = id name;
          group = "svc";
        };
      };
      # The timer starts in the rotation subtest only, without its random delay.
      systemd.timers.hanko-node.wantedBy = lib.mkForce [ ];
      systemd.timers.hanko-node.timerConfig.RandomizedDelaySec = lib.mkForce 0;

      # The service: its own user and group (ADR 0005), started by the test once its files exist.
      users.users.svc = {
        isSystemUser = true;
        group = "svc";
      };
      users.groups.svc = { };
      systemd.services.svc.serviceConfig = {
        User = "svc";
        Group = "svc";
        ExecStart = "${python} ${svc} serve ${id peer}";
      };
      networking.firewall.allowedTCPPorts = [ 8443 ];
    };
in
pkgs.testers.runNixOSTest {
  name = "hanko-internal";

  nodes = {
    ca =
      { nodes, ... }:
      {
        imports = [ self.nixosModules.ca ];
        services.hanko-ca = {
          enable = true;
          keyFile = "${caMaterial}/ca.key";
          certFile = "/etc/hanko-ca/ca.pem";
          listen = "${nodes.ca.networking.primaryIPAddress}:4900";
          svidLifetime = lifetime;
          hosts.${nodes.alpha.networking.primaryIPAddress} = [ (id "alpha") ];
          hosts.${nodes.beta.networking.primaryIPAddress} = [ (id "beta") ];
        };
        # A copy, not a store link, so the rotation subtest can append the next CA.
        environment.etc."hanko-ca/ca.pem" = {
          source = "${caMaterial}/ca.pem";
          mode = "0644";
        };
        networking.firewall.allowedTCPPorts = [ 4900 ];
      };
    alpha = host "alpha" "beta";
    beta = host "beta" "alpha";
  };

  testScript =
    { nodes, ... }:
    ''
      ca_ip = "${nodes.ca.networking.primaryIPAddress}"
      alpha_ip = "${nodes.alpha.networking.primaryIPAddress}"
      beta_ip = "${nodes.beta.networking.primaryIPAddress}"
      alpha_id, beta_id = "${id "alpha"}", "${id "beta"}"
      # hanko-node runs, hanko reports (ADR 0014); both as user hanko (ADR 0011).
      node_bin = "${lib.getExe' nodes.alpha.services.hanko-node.package "hanko-node"}"
      as_hanko = "runuser -u hanko -- env STATE_DIRECTORY=/var/lib/hanko ${lib.getExe' nodes.alpha.services.hanko-node.package "hanko"}"
      start_renew = "systemctl reset-failed hanko-node-renew.service; systemctl start hanko-node-renew.service"
      hosts = [(alpha, alpha_id, beta, beta_id, beta_ip), (beta, beta_id, alpha, alpha_id, alpha_ip)]

      def journal(unit: str) -> str:
          return f"journalctl --no-pager _SYSTEMD_UNIT={unit} -o cat"

      def invocation(m: QemuMachine, unit: str) -> str:
          """The lines of the unit's last run only."""
          inv = m.succeed(f"systemctl show -P InvocationID {unit}").strip()
          return m.succeed(f"journalctl --no-pager _SYSTEMD_INVOCATION_ID={inv} -o cat")

      def call(m: QemuMachine, peer_id: str, address: str) -> str:
          """Calls the peer's service; returns the serial of the SVID it presented."""
          serial, answer = m.succeed(f"${python} ${svc} call {peer_id} {address}").split()
          assert answer == "hello", answer
          return serial

      start_all()
      ca.wait_for_unit("hanko-ca.service")
      ca.wait_for_open_port(4900, ca_ip)

      with subtest("each host gets an SVID for its own ID, readable by its service only"):
          for m, me, _, _, _ in hosts:
              m.wait_for_unit("multi-user.target")
              m.succeed(start_renew)
              files = " ".join(f"/var/lib/hanko/svc/{f}.pem" for f in ["svid", "key", "bundle"])
              out = m.succeed(f"stat -c '%a %U %G' {files}")
              assert out == "640 hanko svc\n" * 3, out
              out = m.succeed("openssl x509 -noout -ext subjectAltName,extendedKeyUsage -in /var/lib/hanko/svc/svid.pem")
              assert f"URI:{me}" in out and "DNS:" not in out and "TLS Web Client Authentication" in out, out
              m.succeed("openssl verify -CAfile /var/lib/hanko/svc/bundle.pem /var/lib/hanko/svc/svid.pem")
              m.succeed("runuser -u svc -- cat /var/lib/hanko/svc/key.pem >/dev/null")
              m.fail("runuser -u nobody -- cat /var/lib/hanko/svc/key.pem")
              m.succeed("systemctl start svc.service")
              m.wait_for_open_port(8443)

      with subtest("the services authenticate each other by SPIFFE ID over mutual TLS"):
          for m, me, _, peer_id, peer_ip in hosts:
              call(m, peer_id, peer_ip)
              # A valid SVID with another ID: the server refuses it (its own, here) ...
              m.fail(f"${python} ${svc} call {me} 127.0.0.1")
              # ... and the client refuses a server that is not the one it expects.
              m.fail(f"${python} ${svc} call {me} {peer_ip}")

      with subtest("an ID not allowed for the caller's address is refused"):
          # alpha asks for beta's ID, from its own address, in a state directory of root's.
          alpha.succeed(
              "install -d -m 0751 /root/stolen && install -d -m 2750 /root/stolen/svc",
              "cat > /root/stolen.toml <<EOF\n"
              f'[internal]\nca = "{ca_ip}:4900"\n'
              f'[[certificates]]\nname = "svc"\nissuer = "internal"\ngroup = "root"\nspiffe_id = "{beta_id}"\n'
              "EOF",
          )
          out = alpha.fail(f"STATE_DIRECTORY=/root/stolen {node_bin} run /root/stolen.toml 2>&1")
          assert '"event":"certificate-failed","certificate":"svc"' in out and "PermissionDenied" in out, out
          alpha.fail("test -e /root/stolen/svc/svid.pem")
          out = ca.succeed(journal("hanko-ca.service"))
          assert f'"event":"sign-refused","peer":"{alpha_ip}","spiffe_id":"{beta_id}"' in out, out

      with subtest("a run with nothing due refreshes the bundle (ADR 0012, step (a))"):
          ca.succeed("cat ${caMaterial}/next.pem >> /etc/hanko-ca/ca.pem", "systemctl restart hanko-ca.service")
          ca.wait_for_open_port(4900, ca_ip)
          for m, _, _, peer_id, peer_ip in hosts:
              before = m.succeed("sha256sum < /var/lib/hanko/svc/svid.pem")
              m.succeed(start_renew)
              out = invocation(m, "hanko-node-renew.service")
              assert '"event":"certificate-valid","certificate":"svc"' in out and '"event":"bundle-written","certificate":"svc"' in out, out
              assert m.succeed("sha256sum < /var/lib/hanko/svc/svid.pem") == before
              assert m.succeed("grep -c 'BEGIN CERTIFICATE' /var/lib/hanko/svc/bundle.pem").strip() == "2"
              m.succeed("openssl verify -CAfile /var/lib/hanko/svc/bundle.pem /var/lib/hanko/svc/svid.pem")
          for m, _, _, peer_id, peer_ip in hosts:
              call(m, peer_id, peer_ip)

      with subtest("the timer renews both SVIDs and the services serve them, no reload, no restart"):
          pids = {m.name: m.succeed("systemctl show -P MainPID svc.service") for m, *_ in hosts}
          served = {m.name: call(m, peer_id, peer_ip) for m, _, _, peer_id, peer_ip in hosts}
          for m, *_ in hosts:
              m.succeed("systemctl start hanko-node.timer")
          for m, _, _, peer_id, peer_ip in hosts:
              # A failed call must not pass for a new serial.
              m.wait_until_succeeds(
                  f"out=$(${python} ${svc} call {peer_id} {peer_ip}) && [ \"$(echo $out | cut -d' ' -f1)\" != {served[m.name]} ]",
                  timeout=900,
              )
          for m, *_ in hosts:
              assert m.succeed("systemctl show -P MainPID svc.service") == pids[m.name]
              assert m.succeed("systemctl show -P NRestarts svc.service").strip() == "0"
              # svc picked the files up itself; systemd never reloaded it and hanko sent nothing.
              out = m.succeed("journalctl --no-pager -u svc.service")
              assert "files-changed" in out and "Reloading" not in out and "Reloaded" not in out, out
              out = m.succeed(journal("hanko-node-renew.service")) + m.succeed(journal("hanko-node.service"))
              assert '"reason":"less than half of its lifetime left"' in out, out
              assert '"event":"reload-' not in out, out
              # No polkit rule: hanko could not reload or restart svc if it tried (ADR 0005).
              m.fail("test -e /etc/polkit-1/rules.d/10-nixos.rules && grep -q hanko /etc/polkit-1/rules.d/10-nixos.rules")
              m.succeed("openssl verify -CAfile /var/lib/hanko/svc/bundle.pem /var/lib/hanko/svc/svid.pem")

      with subtest("hanko status shows the SVID and the expiry of the CA that signed it"):
          for m, me, *_ in hosts:
              out = m.succeed(f"{as_hanko} status /etc/hanko/hanko.toml")
              assert f'"level":"info","v":1,"event":"certificate-status","certificate":"svc","issuer":"internal","spiffe_id":"{me}"' in out, out
              assert '"ca_expiring":false,"valid":true' in out and '"ca_not_after":"' in out, out

      with subtest("every line hanko and hanko-ca wrote passes the log schema (ADR 0007)"):
          # Empty input passes the validator: first prove the events are there.
          for m, unit, events in [
              (alpha, "hanko-node-renew.service", ["certificate-renewing", "certificate-written", "certificate-valid", "bundle-written", "run-completed"]),
              (beta, "hanko-node-renew.service", ["certificate-written", "bundle-written", "run-completed"]),
              (alpha, "hanko-node.service", ["run-completed"]),
              (ca, "hanko-ca.service", ["ca-started", "svid-signed", "sign-refused"]),
          ]:
              out = m.succeed(journal(unit))
              for e in events:
                  assert f'"event":"{e}"' in out, out
              m.succeed(f"{journal(unit)} | ${validateLogs} validate --logs")
    '';
}
