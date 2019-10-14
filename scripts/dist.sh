#!/bin/bash

# 1. commit to bump the version and update the changelog/readme
# 2. tag that commit
# 3. use dist.sh to produce tar.gz
# 4. update the release metadata on github / upload the binaries there too

set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
rm -rf   $DIR/dist
mkdir -p $DIR/dist

arch=$(go env GOARCH)
version='2.1.0'
goversion=$(go version | awk '{print $3}')

echo "... building v$version for $linux/$arch"
TARGET="sso-$version-linux-$arch-$goversion"
GOOS=linux GOARCH=amd64\
    make build
sudo chown -R 0:0 dist
echo "...tar-ing dist to $TARGET"
cd dist && tar czvf ../$TARGET.tar.gz . && cd -
