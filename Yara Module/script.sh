#!/bin/bash

echo ""

# Command that produces the output
command_output=$(yara rules.yar $1 -w -m)

count=$(yara rules.yar $1 -c -w)

yararulefirstline="^[^ ]+"

# Iterate over each line in the command output
if [ "$count" -ne 0 ]; then

	while IFS= read -r line; do
    		# Use regex matching on each line
    		if [[ "$line" =~ $yararulefirstline ]]; then
        		echo "${BASH_REMATCH[0]}"
    		#else
    		#    echo "Pattern 1 not found in: $line"
    		fi

    	if [[ "$line" =~ description=\"[^\"]*\" ]]; then
        	echo "${BASH_REMATCH[0]}"
    	else
		if [[ "$line" =~ desc=\"([^\"]*)\" ]]; then
			echo "${BASH_REMATCH[0]}"
		else

        		echo "Description not found"
		fi
    	fi

	echo ""
   
    	# Run additional regex matching or perform other operations
    	# ...
	done <<< "$command_output"

fi

echo "Matches found: $count"
