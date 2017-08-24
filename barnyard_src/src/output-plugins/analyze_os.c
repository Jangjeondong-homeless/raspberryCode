#include <mysql.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char* argv[]){
    FILE *wfp = fopen("/usr/src/barnyard_src/src/output-plugins/output.txt", "w");
    MYSQL *conn = mysql_init(NULL);
    mysql_real_connect(conn, "localhost", "snort", "MYPASSWORD", "snort", 0, NULL, 0);
    MYSQL_RES *sql_result;
    MYSQL_ROW sql_row;
    int query_stat;
    char statement[512];
    //char sid[10] = &argv[1];
    //printf("%s\n",argv[1]);
    snprintf(statement,512,"SELECT cve FROM sid_cve WHERE sid = '%s'",argv[1]);
    query_stat = mysql_query(conn,statement);
    if(query_stat != 0) {
	    printf("select Mysql query error : %s",mysql_error(conn));
	    exit(1);
    }
    sql_result = mysql_store_result(conn);
    int fields = mysql_num_fields(sql_result);
    printf("%d\n",fields);
    sql_row = mysql_fetch_row(sql_result);
    if(sql_row == NULL){
        puts("sql_row null");
    } else {
	//printf("%d\n",sizeof(sql_row[0]));
        printf("%s\n",sql_row[0]);
    }
    return 0;
}

