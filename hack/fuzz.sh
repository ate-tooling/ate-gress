#!/usr/bin/env bash
# Finds and runs the Go fuzz targets. `make fuzz` and the fuzz workflow both
# go through here, so a new `func FuzzX(f *testing.F)` is picked up by both
# without being listed anywhere.
#
#   hack/fuzz.sh list                    every target, as "<package> <target>"
#   hack/fuzz.sh changed <base commit>   the targets a change since <base commit> can affect
#   hack/fuzz.sh matrix [<base commit>]  the same as list, or changed, as a JSON array
#   hack/fuzz.sh run <package> <target> [fuzztime]
#   hack/fuzz.sh all [fuzztime]
#
# A failing input is written by `go test` to the package's
# testdata/fuzz/<target>/ directory. That file is the reproducer: `go test`
# runs every file there as a regression test, so committing it with the fix
# is how a crash stays fixed.

set -o errexit -o nounset -o pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${root}"

# Files a package's targets read that are not Go packages they import.
extra_inputs() {
  case "$1" in
  # FuzzSchemaAgreesWithCompiler reads the path pattern out of the CRD.
  ./internal/policy) echo "config/crd/" ;;
  esac
}

# A change to any of these can affect every target.
everything='^(go\.mod|go\.sum|hack/fuzz\.sh|\.github/workflows/fuzz\.yaml)$'

list() {
  grep -rEo --include='*_test.go' '^func Fuzz[A-Za-z0-9_]+\(' api cmd internal test |
    sed -E 's|^(.*)/[^/]+_test\.go:func (Fuzz[A-Za-z0-9_]+)\($|./\1 \2|' |
    LC_ALL=C sort
}

# in_module_dirs PACKAGE prints the directories, relative to the repository,
# of the package, its tests, and everything in this module they import.
in_module_dirs() {
  go list -deps -test -f '{{if not .Standard}}{{.Dir}}{{end}}' "$1" |
    sed -n "s|^${root}/||p" | LC_ALL=C sort -u
}

changed() {
  local base=$1 files pkg target dir file hit
  files="$(git diff --name-only "${base}...HEAD")"
  if grep -Eq "${everything}" <<<"${files}"; then
    list
    return
  fi
  while read -r pkg target; do
    hit=0
    for dir in $(in_module_dirs "${pkg}") $(extra_inputs "${pkg}"); do
      dir="${dir%/}"
      while read -r file; do
        # A package is the files directly in its directory, and its testdata.
        if [[ "$(dirname "${file}")" == "${dir}" || "${file}" == "${dir}/testdata/"* ]]; then
          hit=1
          break 2
        fi
      done <<<"${files}"
    done
    if [[ ${hit} -eq 1 ]]; then echo "${pkg} ${target}"; fi
  done < <(list)
}

matrix() {
  local sep="" pkg target
  printf '['
  while read -r pkg target; do
    [[ -n "${pkg}" ]] || continue
    printf '%s{"package":"%s","target":"%s"}' "${sep}" "${pkg}" "${target}"
    sep=","
  done
  printf ']\n'
}

# new_inputs prints the corpus files `go test` wrote that git does not know.
new_inputs() {
  git ls-files --others --exclude-standard -- '*/testdata/fuzz/*'
}

run() {
  local pkg=$1 target=$2 fuzztime=${3:-10s} status=0 file
  go test -run='^$' -fuzz="^${target}\$" -fuzztime="${fuzztime}" "${pkg}" || status=$?
  if [[ ${status} -ne 0 ]]; then
    while read -r file; do
      [[ -n "${file}" ]] || continue
      # shellcheck disable=SC2016 # the backticks are Markdown
      {
        printf '### %s failed on a new input\n\n' "${target}"
        printf 'Reproduce with `go test -run='"'"'^%s$/%s'"'"' %s` after saving this as `%s`:\n\n' \
          "${target}" "$(basename "${file}")" "${pkg}" "${file}"
        printf '```\n%s\n```\n\n' "$(cat "${file}")"
        printf 'Commit the file with the fix: `go test` then runs it as a regression test.\n'
      } | tee -a "${GITHUB_STEP_SUMMARY:-/dev/null}"
    done < <(new_inputs)
  fi
  return "${status}"
}

case "${1:-}" in
list)
  list
  ;;
changed)
  [[ $# -eq 2 ]] || { echo "usage: $0 changed <base commit>" >&2; exit 2; }
  changed "$2"
  ;;
matrix)
  if [[ $# -ge 2 && -n "$2" ]]; then changed "$2" | matrix; else list | matrix; fi
  ;;
run)
  [[ $# -ge 3 ]] || { echo "usage: $0 run <package> <target> [fuzztime]" >&2; exit 2; }
  run "$2" "$3" "${4:-}"
  ;;
all)
  while read -r pkg target; do
    run "${pkg}" "${target}" "${2:-}"
  done < <(list)
  ;;
*)
  sed -n '2,/^$/s/^# \{0,1\}//p' "${BASH_SOURCE[0]}" >&2
  exit 2
  ;;
esac
