#!/bin/bash

rm bin/*

make clean
make generate
make all

TESTS=$(ls bin)

for i in $( ls bin ); do
./bin/$i
done


