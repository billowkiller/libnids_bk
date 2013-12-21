#!/bin/sh

sudo make clean
./configure && make
sudo make install
