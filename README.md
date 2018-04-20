# golm [![Build Status](https://travis-ci.org/targodan/golm.svg?branch=master)](https://travis-ci.org/targodan/golm) [![Coverage Status](https://coveralls.io/repos/github/targodan/golm/badge.svg?branch=master)](https://coveralls.io/github/targodan/golm?branch=master)

A go binding for the libolm cryptographic library.

## Naming

The names of the Go functions are very close to the names of the C functions. We may strip some prefixes but we won't *rename* functions.

Only exception to this is `create-` functions they are renamed to `New-` functions, in order to make it feel more like Go.

If you are looking for a specific C function go to the [documentation of this binding](https://godoc.org/github.com/targodan/golm) and simply search for it there.

## Behaviour

This binding strives to make the libolm feel like go. As a result this library *should only ever* panic if the developer did something wrong in a static way.

Say you have a nil pointer and call something on it: Panicing is fine.
Say you call a function with a string you receive from outside and it happens to be empty: It should not panic.

If you get this binding to panic please open an issue so we can handle the erroneous input in a non-panicy way.

## Coverage

Take the code coverage here with a pinch of salt. This being a binding for an already tested library, we are mostly only testing for it to not panic. In some cases we make some plausibility checks but we almost never test for "correct output", that's the task of the libolm developers.

If you find a bug feel free to open an issue, but be aware that it may be an upstream bug. If you have the time, please check if the bug is upstream. Doing so would require to do the same thing you did with this binding with a small C program, using the library directly. If the same error occurs in the C program the error comes from upstream.

[Upstream bugs can be reported here.](https://github.com/matrix-org/olm/issues)
