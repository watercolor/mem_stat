#!/bin/bash
if [ $2 == "mips" ]; then
    CROSS_COMPILE=mips64-octeon-linux-gnu-
fi
echo "Generate symbol list for $1 ..."
${CROSS_COMPILE}nm -n $1 > $1.sym.list
sed -e "/^ /d" $1.sym.list > $1.sym.list2
cp -f symbol_parse_orig.c symbol_parse.c
awk 'BEGIN {printf "symbol_info symbol_array[] = {\n"} \
           {printf "    { 0x%s, \"%s\", '\''%c'\''},\n", $1, $3, $2} \
       END {printf "};\nint symbol_array_size = sizeof(symbol_array)/sizeof(symbol_array[0]);"}' \
    $1.sym.list2 >> symbol_parse.c
echo "Compilee library..."
${CROSS_COMPILE}gcc -fPIC -c -ggdb symbol_parse.c -o symbol_parse.o
${CROSS_COMPILE}gcc -fPIC -shared symbol_parse.o -o libsymbol.so
echo "Clean temporary files..."
rm -f $1.sym.list $1.sym.list2 symbol_parse.o #symbol_parse.c
