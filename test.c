/* #include <libunwind.h> */
#include <stdio.h>
#include <time.h>
#if 0
void do_unwind_backtrace()
{
    unw_cursor_t    cursor;
    unw_context_t   context;

    unw_getcontext(&context);
    unw_init_local(&cursor, &context);

    while (unw_step(&cursor) > 0) {
        unw_word_t  offset, pc;
        char        fname[64];

        unw_get_reg(&cursor, UNW_REG_IP, &pc);

        fname[0] = '\0';
        (void) unw_get_proc_name(&cursor, fname, sizeof(fname), &offset);

        printf ("%p : (%s+0x%x) [%p]\n", pc, fname, offset, pc);
    }
    printf("---------------------------------------------------------\n");
}

void bar()
{
    do_unwind_backtrace();
    return;
}
void foo()
{
    bar();
    return;
}
#endif

typedef struct time_val_base {
    int yeartime;
    int monthtime;
    int daytime;
    int hourtime;
    int minutetime;
    int seconds;
}timebase_t;

timebase_t g_timebase = {
    .yeartime   = 365*24*3600,
    .monthtime  = 30*24*3600,
    .daytime    = 24*3600,
    .hourtime   = 3600,
    .minutetime = 60,
    .seconds    = 1,
};

time_t printtime()
{
    time_t now = time(NULL);
    time_t least;
    struct tm time_val;
    time_val.tm_year = now/g_timebase.yeartime;
    least = now - time_val.tm_year * g_timebase.yeartime;

    time_val.tm_mon = least/g_timebase.monthtime;
    least = least - time_val.tm_mon * g_timebase.monthtime;

    time_val.tm_mday = least/g_timebase.daytime;
    least = least - time_val.tm_mday * g_timebase.daytime;

    time_val.tm_hour = least/g_timebase.hourtime;
    least = least - time_val.tm_hour * g_timebase.hourtime;

    time_val.tm_min = least/g_timebase.minutetime;
    least = least - time_val.tm_min * g_timebase.minutetime;

    time_val.tm_sec = least;

    printf("%d %d %d %d %d %d\n", 1970 + time_val.tm_year, time_val.tm_mon,
    		time_val.tm_mday, time_val.tm_hour, time_val.tm_min, time_val.tm_sec);
    return now;
}
int main(int argc, const char *argv[])
{
	printtime();
    return 0;
}
