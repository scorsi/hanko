{
  lib,
  buildGoModule,
  src,
}:
buildGoModule {
  pname = "hanko";
  version = "0.0.0-dev";
  inherit src;

  # Changes whenever go.sum does: set to lib.fakeHash and read the new value from the build error.
  vendorHash = "sha256-2FTMhWgivUY7En7W6ktuBcyDwbTHbpKZnPZWXBgC4i0=";

  ldflags = [
    "-s"
    "-w"
  ];

  # `nix flake check` runs this phase: vet first, then the default `go test ./...`.
  preCheck = ''
    go vet ./...
  '';

  meta = {
    description = "Certificate service for a Nix-managed homelab";
    license = lib.licenses.asl20;
    mainProgram = "hanko";
  };
}
