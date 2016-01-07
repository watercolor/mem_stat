# mem_stat
A simple memory alloc and free statics library

Usage:
1. run make to get libmmstat.so, if you want cross-compile, use make CROSS=XXXXXX
2. cp libmmstat.so to somewhere, like "/lib64"
3. execute the following commands in linux shell, set enviroment.
export LD_PRELOAD="/lib64/libmmstat.so"
export LD_PRELOAD_64="/lib64/libmmstat.so"

4. then start you bin, the libmmstat.so will replace default malloc and free automatically.

5. or you can not jump step3,4, manually run bin with PRELOAD prefix, likes:
LD_PRELOAD="/lib64/libmmstat.so" LD_PRELOAD_64="/lib64/libmmstat.so" /you/program

Have fun :)

