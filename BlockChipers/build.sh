mkdir build_dir
cd build_dir
echo "Entering build_dir directory"
echo "Compiling source code"
gcc -g -c ../AES/AES.c \
	../DES/DES.c \
	../Modes/Modes.c \
	../Padding/Symetric_Padding.c \
	../RC6/RC6.c \
	../Block_API.c \
	../test/test.c
echo "Linking objects"
cd ../test
gcc ../build_dir/*.o -o app
echo "Leaving directory"
cd ..
echo "Cleaning up"
rm -rdf build_dir
