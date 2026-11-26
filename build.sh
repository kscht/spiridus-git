#!/bin/sh
# Версионные бинарники и SHA-256; публикация и подпись выпуска — отдельное действие lead.
set -eu
exec </dev/null
: "${TMPDIR:?Нужен TMPDIR}"
: "${SPIRIDUS_GO_BIN:?Нужен Go 1.25.3 (SPIRIDUS_GO_BIN)}"
[ "$("$SPIRIDUS_GO_BIN" version | cut -d ' ' -f 3)" = go1.25.3 ]
client_output=${1:?Нужен каталог для результата}
mkdir -p "$client_output"
client_output=$(cd "$client_output" && pwd)
cd "$(dirname "$0")"
export GOTOOLCHAIN=local CGO_ENABLED=0
for client_os in linux darwin windows; do
  for client_arch in amd64 arm64; do
    client_suffix=''
    if [ "$client_os" = windows ]; then client_suffix=.exe; fi
    GOOS="$client_os" GOARCH="$client_arch" "$SPIRIDUS_GO_BIN" build -mod=readonly -buildvcs=false -trimpath -ldflags='-s -w' -o "$client_output/git-remote-spiridus-0.1.1-$client_os-$client_arch$client_suffix" .
  done
done
cp LICENSE NOTICE THIRD_PARTY_NOTICES.txt "$client_output/"
(cd "$client_output" && sha256sum git-remote-spiridus-* > SHA256SUMS)
