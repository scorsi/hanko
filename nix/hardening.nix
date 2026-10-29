# Service hardening shared by hanko and hanko-ca (ADR 0005).
{
  # Default new files to owner-only; hanko's explicit chmod(0640) still permits certificate consumers.
  UMask = "0077";
  LimitCORE = 0; # Private keys must not land in ordinary core files.
  CoredumpFilter = "0x0"; # Exclude memory mappings even when the host pipes dumps to a collector.
  ProtectKernelTunables = true; # No sysctl writes.
  ProtectKernelModules = true; # No module loading or module-tree access.
  ProtectKernelLogs = true; # No kernel log access.
  ProtectControlGroups = true; # No cgroup management.
  ProtectClock = true; # TLS needs clock reads, never clock changes.
  RestrictNamespaces = true; # Neither Go nor systemctl creates namespaces.
  RestrictRealtime = true; # No realtime scheduling is needed.
  RestrictSUIDSGID = true; # No set-id files; hanko's setgid certificate directories are provisioned outside the unit.
  LockPersonality = true; # hanko, systemctl and hanko-ca use the native process personality.
  SystemCallArchitectures = "native"; # No foreign-ABI executables.
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
}
