#!/bin/bash

# Command that produces the output
command_output=$(yara index.yar mal6.js -w -m)

# Iterate over each line in the command output
while IFS= read -r line; do
    # Use regex matching on each line
    if [[ "$line" =~ ^([[:alnum:]]+) ]]; then
        echo "${BASH_REMATCH[0]}"
    #else
    #    echo "Pattern 1 not found in: $line"
    fi

    if [[ "$line" =~ description=\"[^\"]*\" ]]; then
        echo "${BASH_REMATCH[0]}"
    else
        echo "Description not found"
    fi

    echo ""
    
    # Run additional regex matching or perform other operations
    # ...
done <<< "$command_output"

