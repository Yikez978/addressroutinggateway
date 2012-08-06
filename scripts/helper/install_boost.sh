#!/bin/bash
BOOST_DIR=~/src/boost
if [ ! -e "$BOOST_DIR" ]
then
	echo Download boost...
	mkdir -p "$BOOST_DIR"
	svn co http://svn.boost.org/svn/boost/trunk "$BOOST_DIR"
	cd "$BOOST_DIR"
else
	echo Updating boost SVN...
	cd "$BOOST_DIR"
	svn up 
fi

echo Building boost...
./bootstrap.sh --with-libraries=program_options,thread,date_time
./b2

echo Installing...
sudo ./bjam install

echo Done!

