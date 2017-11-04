#include <stdio.h>
#include <string.h>

#include <ngx_core.h>

#include <king_mysql/king_mysql.h>

char *host = "localhost";
char *user = "root";
char *passwd = "sgy2017";
char *db = "test";
int port = 3306;

int test_mysql(int a, int b, ngx_log_t *log)
{
    king_mysql_t mysql_info;
    int ret = 0;

    memset(&mysql_info, 0, sizeof(mysql_info));

    ret = king_mysql_init(&mysql_info, host, port, user, passwd, db);
    if (ret < 0)
    {
        ngx_log_error(NGX_LOG_EMERG, log, 0,
                "ngx mysql init failed");
    }

    ngx_log_error(NGX_LOG_EMERG, log, 0,
            "mysql init success");

    ret = a + b;
    return ret;
}

