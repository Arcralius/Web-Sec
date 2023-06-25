#!/bin/bash

echo ""

folder_path=$1

# Recursively find all files and print their names
files=$(find "$folder_path" -type f -print)

while IFS= read -r fileline; do

	escaped_file_path=$(echo "$fileline" | sed 's/ /_/g')
	escape=$(printf "%q" "$fileline")

	# Command that produces the output

	command_output=$(yara rules.yar $fileline -w -m)

	commandescape=$(printf "%q" "$command_output")
	count=$(yara rules.yar $escape -c -w)

	echo ""
	echo "-------------------------------------------------------------"
	echo "file name: $fileline"

	yararulefirstline="^[^ ]+"

	# Iterate over each line in the command output
	if [ "$count" -ne 0 ]; then

		while IFS= read -r line; do
			# Use regex matching on each line
			if [[ "$line" =~ $yararulefirstline ]]; then
				echo ""
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
		done <<< "$commandescape"

	fi

	echo "Matches found: $count"

done <<< "$files"