{ pkgs, lib, config, inputs, ... }:

{
  packages = with pkgs; [
    bacon
    cargo-audit
    cargo-edit
    cargo-license
    cargo-nextest
    cargo-shear
    cargo-deny
  ];

  languages.rust = {
    enable = true;
    channel = "stable";
    mold.enable = true;
  };

  git-hooks.hooks = {
    clippy.enable = true;
    commitizen.enable = true;
    rustfmt.enable = true;
    trufflehog.enable = true;
  };

  scripts = {
    pre-check = {
      description = "Run all pre-check scripts";
      exec = ''
        set -e
        echo "Running pre-check scripts..."
        cargo clippy --all-targets --all-features -- -Dclippy::all
        cargo nextest run
        cargo audit
        cargo deny check
      '';
    };
  };
}
