#!/usr/bin/env bash

# The legacy WSL share also works when Windows cannot resolve wsl.localhost.
windows_path() {
  local path
  path="$(wslpath -w "$1")" || return
  printf '%s\n' "${path/#\\\\wsl.localhost\\/\\\\wsl\$\\}"
}

# A Linux working directory may resolve through the unavailable share as well.
windows_powershell() (
  cd /mnt/c || return
  /mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe "$@"
)
