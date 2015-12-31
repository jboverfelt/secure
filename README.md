# Go Challenge 2 [![Build Status](https://travis-ci.org/jboverfelt/secure.svg?branch=master)](https://travis-ci.org/jboverfelt/secure) [![GoDoc](https://godoc.org/github.com/jboverfelt/secure?status.svg)](https://godoc.org/github.com/jboverfelt/secure)

Securing data transmission using NaCl.

More information [here](http://golang-challenge.com/go-challenge2/)

*Note:* This is an updated version based on evaluator feedback. The original is
[here](https://github.com/golangchallenge/GCSolutions/tree/master/april15/normal/justin-overfelt/jboverfelt-secure-f96ca7e9bc9a)

## Installation/Usage

This package requires Go 1.5 or later, as it uses the vendoring support found in Go 1.5
If you're using Go 1.6 or later, setting the environment variable as described below is unnecessary.

``go get -u github.com/jboverfelt/secure``

Then, ensure that the following environment variable is set: GO15VENDOREXPERIMENT=1

To build the included command, change to the cmd/challenge2 directory and run ``go build``

Tests were split up into two files, one for the library and one for the command
