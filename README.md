# Files for SSTIC 2021 presentations

This repository contains the source files for some presentations which were given at SSTIC 2021:

* [Protecting SSH authentication with TPM 2.0](https://www.sstic.org/2021/presentation/protecting_ssh_authentication_with_tpm_20/)
* [Analyzing ARCompact firmware with Ghidra](https://www.sstic.org/2021/presentation/analyzing_arcompact_firmware_with_ghidra/)

The articles were written in Markdown using [Pandoc](https://pandoc.org/) to produce LaTeX files compatible with [SSTIC author template](https://gitlab.com/sstic/author-template).

Building dependencies:

* `pandoc` to convert Markdown files to LaTeX
* `podman` to build in [`docker.io/sstic/actes` cointainer](https://hub.docker.com/r/sstic/actes)
* `sed` to replace references correctly in the Markdown files.
