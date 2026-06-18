# With `direnv` and `nix`

```bash
direnv allow
```

# With `nix`

```bash
nix develop
```

# Commands

```bash
# run tests
nix flake check

nix build .#endpoint-openpgp-sequoia
nix build .#endpoint

nix run .#endpoint
```
