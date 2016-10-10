#!/bin/sh

socat tcp-listen:4925,fork,reuseaddr exec:./oreo,PTY,raw,echo=0
#qira -s ./oreo
#strace -f socat tcp-listen:4924,fork,reuseaddr exec:./oreo,PTY,raw,echo=0
