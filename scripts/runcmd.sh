#!/bin/bash
cd ~/pushed
for f in runcmd-*.sh
do
	[ -e "$f" ] || break

	echo Running $f
	mv "$f" "temp.$f"
	chmod +x "temp.$f"
	"./temp.$f"
	rm "temp.$f"
done

echo Done

