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
    long yeartime;
    long monthtime[12];
    long daytime;
    long hourtime;
    long minutetime;
    long month_day[12];
}timebase_t;

timebase_t g_timebase = {
    .yeartime   = 365*24*3600,
    .monthtime  = {
        31*24*3600,
        28*24*3600,
        31*24*3600,
        30*24*3600,
        31*24*3600,
        30*24*3600,
        31*24*3600,
        31*24*3600,
        30*24*3600,
        31*24*3600,
        30*24*3600,
        31*24*3600,
    },
    .daytime    = 24*3600,
    .hourtime   = 3600,
    .minutetime = 60,
    .month_day  = {
        31, 28, 31, 30, 31, 30,
        31, 31, 30, 31, 30, 31,
    }
};

long leapyear_round_time_cost = 4*365*24*3600 + 24*3600;

long leapyear_step[] = {
    365*24*3600,  /* 1970 */
    365*24*3600,  /* 1971 */
    366*24*3600,  /* 1972 */
    365*24*3600,  /* 1973 */
};

static inline int isleapyear(int year)
{
    return  (((year % 4) ==0) && (((year % 100) != 0) || ((year % 400) == 0)));
}

int calc_gmt_tm(time_t input_time, struct tm* out_tm)
{
    time_t time_source = input_time;
    time_t least;
    struct tm time_val;
    int tmp = 0;

    if (time_source == 0) {
        time_source = time(NULL);
    }
    tmp = time_source/leapyear_round_time_cost;
    least = time_source - tmp * leapyear_round_time_cost;
    tmp *= 4;
    for (int step = 0; step < 4; step++) {
        if (least > leapyear_step[step]) {
            tmp += 1;
            least -= leapyear_step[step];
        } else {
            break;
        }
    }
    time_val.tm_year = tmp + 1970;

    for (int m_step = 0; m_step < 12; m_step++) {
        int month_sec = g_timebase.monthtime[m_step];
        if(m_step == 1 && isleapyear(time_val.tm_year)) {
            month_sec += g_timebase.daytime;
        }
        if (least > month_sec) {
            least -= month_sec;
        } else {
            time_val.tm_mon = m_step + 1;
            break;
        }
    }

    time_val.tm_mday = least/g_timebase.daytime;
    least = least - time_val.tm_mday * g_timebase.daytime;
    time_val.tm_mday += 1;

    time_val.tm_hour = least/g_timebase.hourtime;
    least = least - time_val.tm_hour * g_timebase.hourtime;

    time_val.tm_min = least/g_timebase.minutetime;
    least = least - time_val.tm_min * g_timebase.minutetime;

    time_val.tm_sec = least;

    printf("%d %d %d %d %d %d\n", time_val.tm_year, time_val.tm_mon,
    		time_val.tm_mday, time_val.tm_hour, time_val.tm_min, time_val.tm_sec);
    if (out_tm) {
        out_tm->tm_year = time_val.tm_year;
        out_tm->tm_mon  = time_val.tm_mon;
        out_tm->tm_mday = time_val.tm_mday;
        out_tm->tm_hour = time_val.tm_hour;
        out_tm->tm_min  = time_val.tm_min;
        out_tm->tm_sec  = time_val.tm_sec;

    }
    return 0;
}

struct tm* calc_china_tm(time_t input_time, struct tm* out_tm)
{
#define CHINA_TIME_ZONE  8
    int month_last_day;
    calc_gmt_tm(input_time, out_tm);

    month_last_day = g_timebase.month_day[out_tm->tm_mon] + isleapyear(out_tm->tm_year);
    if(out_tm) {
        out_tm->tm_hour += CHINA_TIME_ZONE;
        if (out_tm->tm_hour > 24) {
            out_tm->tm_hour -= 24;
            out_tm->tm_mday += 1;
            if (out_tm->tm_mday > month_last_day) {
                out_tm->tm_mday = 1;
                out_tm->tm_mon += 1;
                if (out_tm->tm_mon > 12) {
                    out_tm->tm_mon = 1;
                    out_tm->tm_year += 1;
                }
            }
        }
    }
    return out_tm;
}

int main(int argc, const char *argv[])
{
	calc_gmt_tm(0, NULL);
    return 0;
}
