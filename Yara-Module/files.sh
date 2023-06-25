#!/bin/bash

folder_path=$1

# Recursively find all files and print their names
find "$folder_path" -type f -print

