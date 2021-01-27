#!/bin/sh

set -u

matcher=$(cat <<'EOF'
set print-matcher true
enable output detailed-ast

### Expressions of any floating point type (unless in a system header)
match expr(allOf(unless(isExpansionInSystemHeader()), hasType(realFloatingPointType())))

### Calls to memcmp (secp256k1_memcmp_var should be used instead)
match callExpr(callee(functionDecl(hasName("memcmp"))))

### Reserved identifiers (unless in a system header) with external linkage or at file scope.
# Any function is in file scope. Any variable with static storage (unless static local variable) is in file scope.
# Allowed exceptions: __builtin_expect
# We need the "::" due to LLVM bug 47879.
match namedDecl(allOf(unless(isExpansionInSystemHeader()), anyOf(hasExternalFormalLinkage(), functionDecl(), varDecl(allOf(hasStaticStorageDuration(), unless(isStaticLocal())))), allOf(matchesName("^::(_|((mem|is|to|str|wcs)[a-z]))"), unless(hasAnyName("__builtin_expect")))))

### Reserved type names (unless in a system header)
# Allowed exceptions: uint128_t, int128_t, __int128_t, __uint128_t (the latter two are "implicit", i.e., added by the compiler)
match typedefDecl(allOf(unless(isExpansionInSystemHeader()), matchesName("(^::u?int)|(_t$)"), unless(hasAnyName("int128_t", "uint128_t", "__int128_t", "__uint128_t"))))

quit
EOF
)

# Poor man's JSON parser.
# This is not great but it works with the output of all common tools and it does not need extra dependencies.
files=$(grep 'file' compile_commands.json | uniq | cut -d '"' -f 4)
echo "Running clang-query on files:"
echo "$files"

output=$(echo "$matcher" | ${CLANG_QUERY:-clang-query} "$@" $files)
status=$?
echo "$output"
echo
exit $status
