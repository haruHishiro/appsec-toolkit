#!/usr/bin/env bash
set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKG="$(basename "$DIR")"
cd "$(dirname "$DIR")"

case "${1:-help}" in
    h|helper)      python -m "${PKG}.helper" ;;
    c|cheat|cs)    python -m "${PKG}.cheatsheet" ;;
    e|ex|examples) python -m "${PKG}.examples" ;;
    t|test|tests)  python -m pytest "${PKG}/tests" -v ;;
    *)
        echo "Usage: $0 {helper|cheatsheet|examples|tests}"
        ;;
esac
