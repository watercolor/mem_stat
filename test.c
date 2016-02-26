#include <stdio.h>
#include <time.h>

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

void calc_gmt_tm(time_t input_time, struct tm* out_tm)
{
    time_t time_source = input_time;
    time_t least;
    struct tm time_val;
    int tmp = 0;
    int step, m_step;

    if (time_source == 0) {
        time_source = time(NULL);
    }
    tmp = time_source/leapyear_round_time_cost;
    least = time_source - tmp * leapyear_round_time_cost;
    tmp *= 4;
    for (step = 0; step < 4; step++) {
        if (least > leapyear_step[step]) {
            tmp += 1;
            least -= leapyear_step[step];
        } else {
            break;
        }
    }
    time_val.tm_year = tmp + 70;

    time_val.tm_mon = 0;
    for (m_step = 0; m_step < 12; m_step++) {
        int month_sec = g_timebase.monthtime[m_step];
        if(m_step == 1 && isleapyear(time_val.tm_year)) {
            month_sec += g_timebase.daytime;
        }
        if (least > month_sec) {
            least -= month_sec;
        } else {
            time_val.tm_mon = m_step;
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

    /* printf("%d %d %d %d %d %d\n", time_val.tm_year, time_val.tm_mon, */
            /* time_val.tm_mday, time_val.tm_hour, time_val.tm_min, time_val.tm_sec); */
    if (out_tm) {
        out_tm->tm_year = time_val.tm_year;
        out_tm->tm_mon  = time_val.tm_mon;
        out_tm->tm_mday = time_val.tm_mday;
        out_tm->tm_hour = time_val.tm_hour;
        out_tm->tm_min  = time_val.tm_min;
        out_tm->tm_sec  = time_val.tm_sec;
    }
}

void calc_timezone_tm(time_t input_time, struct tm* out_tm, int timezone)
{
    int month_last_day;
    calc_gmt_tm(input_time, out_tm);

    if(out_tm) {
        out_tm->tm_hour += timezone;
        if (out_tm->tm_hour > 24) {
            out_tm->tm_hour -= 24;
            out_tm->tm_mday += 1;
            month_last_day = g_timebase.month_day[out_tm->tm_mon] + isleapyear(out_tm->tm_year);
            if (out_tm->tm_mday > month_last_day) {
                out_tm->tm_mday = 1;
                out_tm->tm_mon += 1;
                if (out_tm->tm_mon == 12) {
                    out_tm->tm_mon = 0;
                    out_tm->tm_year += 1;
                }
            }
        } else if (out_tm->tm_hour < 0) {
            out_tm->tm_hour += 24;
            out_tm->tm_mday -= 1;
            if (out_tm->tm_mday < 1) {
                out_tm->tm_mon -= 1;
                if (out_tm->tm_mon < 0 ) {
                    out_tm->tm_mon = 11;
                    out_tm->tm_year -= 1;
                }
                month_last_day = g_timebase.month_day[out_tm->tm_mon] + isleapyear(out_tm->tm_year);
                out_tm->tm_mday = month_last_day;
            }
        }
    }
}

void calc_china_tm(time_t input_time, struct tm* out_tm)
{
#define CHINA_TIME_ZONE 8
    calc_timezone_tm(input_time, out_tm, CHINA_TIME_ZONE);
}

char* get_local_time(time_t timesrc, char* outbuf, size_t outbuflen)
{
    static char buffer[128];
    char* time_buf = outbuf == NULL ? buffer : outbuf;
    size_t len = outbuf == NULL ? sizeof(buffer) : outbuflen;
    time_t now = timesrc;
    struct tm localtm = {0};
    if (timesrc == 0) {
        now = time(NULL);
    }

    calc_china_tm(now, &localtm);
    snprintf(time_buf, len, "%d-%02d-%02d %02d:%02d:%02d",
            localtm.tm_year + 1900,
            localtm.tm_mon + 1,
            localtm.tm_mday,
            localtm.tm_hour,
            localtm.tm_min,
            localtm.tm_sec
            );
    time_buf[len - 1] = '\0';
    return time_buf;

}
int main(int argc, const char *argv[])
{
    printf("%s\n", get_local_time(0, NULL, 0));
    return 0;
}
