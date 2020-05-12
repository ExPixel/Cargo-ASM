#!/bin/bash

# set -x

documented_packages_list=(\
    shellexpand \
    cargo_metadata \
    anyhow \
    cargo-asm \
    clap \
    gimli \
    capstone \
    goblin \
    pdb \
    rustc-demangle)

documented_packages=""

for p in "${documented_packages_list[@]}"; do
    documented_packages="${documented_packages} -p ${p}"
done

cargo doc --no-deps $documented_packages "${@:1}"
