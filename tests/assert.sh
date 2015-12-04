#!/bin/bash
# assert.sh 1.0 - bash unit testing framework
# Copyright (C) 2009, 2010, 2011, 2012 Robert Lehmann
#
# http://github.com/lehmannro/assert.sh
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

export DISCOVERONLY=${DISCOVERONLY:-}
export DEBUG=${DEBUG:-}
export STOP=${STOP:-}
export INVARIANT=${INVARIANT:-}
export CONTINUE=${CONTINUE:-}

args="$(getopt -n "$0" -l \
    verbose,help,stop,discover,invariant,continue vhxdic $*)" \
|| exit -1
for arg in $args; do
    case "$arg" in
        -h)
            echo "$0 [-vxidc]" \
                "[--verbose] [--stop] [--invariant] [--discover] [--continue]"
            echo "`sed 's/./ /g' <<< "$0"` [-h] [--help]"
            exit 0;;
        --help)
            cat <<EOF
Usage: $0 [options]
Language-agnostic unit tests for subprocesses.

Options:
  -v, --verbose    generate output for every individual test case
  -x, --stop       stop running tests after the first failure
  -i, --invariant  do not measure timings to remain invariant between runs
  -d, --discover   collect test suites only, do not run any tests
  -c, --continue   do not modify exit code to test suite status
  -h               show brief usage information and exit
  --help           show this help message and exit
EOF
            exit 0;;
        -v|--verbose)
            DEBUG=1;;
        -x|--stop)
            STOP=1;;
        -i|--invariant)
            INVARIANT=1;;
        -d|--discover)
            DISCOVERONLY=1;;
        -c|--continue)
            CONTINUE=1;;
    esac
done

printf -v _indent "\n\t" # local format helper

_assert_reset() {
    tests_ran=0
    tests_failed=0
    tests_errors=()
    tests_starttime="$(date +%s.%N)" # seconds_since_epoch.nanoseconds
}

assert_end() {
    # assert_end [suite ..]
    tests_endtime="$(date +%s.%N)"
    tests="$tests_ran ${*:+$* }tests"
    [[ -n "$DISCOVERONLY" ]] && echo "collected $tests." && _assert_reset && return
    [[ -n "$DEBUG" ]] && echo
    [[ -z "$INVARIANT" ]] && report_time=" in $(bc \
        <<< "${tests_endtime%.N} - ${tests_starttime%.N}" \
        | sed -e 's/\.\([0-9]\{0,3\}\)[0-9]*/.\1/' -e 's/^\./0./')s" \
        || report_time=

    if [[ "$tests_failed" -eq 0 ]]; then
        echo "all $tests passed$report_time."
    else
        for error in "${tests_errors[@]}"; do echo "$error"; done
        echo "$tests_failed of $tests failed$report_time."
    fi
    tests_failed_previous=$tests_failed
    [[ $tests_failed -gt 0 ]] && tests_suite_status=1
    _assert_reset
    return $tests_failed_previous
}

assert() {
    # assert <command> <expected stdout> [stdin]
    (( tests_ran++ )) || :
    [[ -n "$DISCOVERONLY" ]] && return || true
    # printf required for formatting
    printf -v expected "x${2:-}" # x required to overwrite older results
    result="$(eval 2>/dev/null $1 <<< ${3:-})" || true
    # Note: $expected is already decorated
    if [[ "x$result" == "$expected" ]]; then
        [[ -n "$DEBUG" ]] && echo -n . || true
        return
    fi
    result="$(sed -e :a -e '$!N;s/\n/\\n/;ta' <<< "$result")"
    [[ -z "$result" ]] && result="nothing" || result="\"$result\""
    [[ -z "$2" ]] && expected="nothing" || expected="\"$2\""
    _assert_fail "expected $expected${_indent}got $result" "$1" "$3"
}

assert_raises() {
    # assert_raises <command> <expected code> [stdin]
    (( tests_ran++ )) || :
    [[ -n "$DISCOVERONLY" ]] && return || true
    status=0
    (eval $1 <<< ${3:-}) > /dev/null 2>&1 || status=$?
    expected=${2:-0}
    if [[ "$status" -eq "$expected" ]]; then
        [[ -n "$DEBUG" ]] && echo -n . || true
        return
    fi
    _assert_fail "program terminated with code $status instead of $expected" "$1" "$3"
}

_assert_fail() {
    # _assert_fail <failure> <command> <stdin>
    [[ -n "$DEBUG" ]] && echo -n X
    report="test #$tests_ran \"$2${3:+ <<< $3}\" failed:${_indent}$1"
    if [[ -n "$STOP" ]]; then
        [[ -n "$DEBUG" ]] && echo
        echo "$report"
        exit 1
    fi
    tests_errors[$tests_failed]="$report"
    (( tests_failed++ )) || :
}

_assert_reset
: ${tests_suite_status:=0}  # remember if any of the tests failed so far
_assert_cleanup() {
    local status=$?
    # modify exit code if it's not already non-zero
    [[ $status -eq 0 && -z $CONTINUE ]] && exit $tests_suite_status
}
trap _assert_cleanup EXIT
