#/bin/sh

if [ $# -lt 1 ]; then
    echo "Usage: $0 script"
    exit 1
fi

export LUA_CPATH="$(dirname $0)/../src/?.so;${LUA_CPATH}"

script=$1
shift
$(dirname $0)/../external/lua/lua $script "$@"
