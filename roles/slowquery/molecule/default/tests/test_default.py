import os

import testinfra.utils.ansible_runner

testinfra_hosts = testinfra.utils.ansible_runner.AnsibleRunner(
    os.environ['MOLECULE_INVENTORY_FILE']).get_hosts('all')


def test_slow_query_enabled(host):
    db_type = host.ansible \
        .get_variables() \
        .get("slowquery_database_type")
    if db_type in ["mysql", "mariadb"]:
        import pymysql
        import pymysql.cursors
        conn = pymysql.connect(
            host='localhost',
            user='root',
            password='root',
            db='slowquery',
            cursorclass=pymysql.cursors.DictCursor)
        try:
            with conn.cursor() as cursor:
                cursor.execute("select sleep(1);")
                cursor.fetchall()
        finally:
            conn.close()
        slow_log = host.file("/tmp/slow_query.log")
        print(slow_log.content_string)
    # PostgreSQL require to restart
    # But Docker container is only restarted by outside of it
    # elif db_type == "postgres":
    #     import psycopg2
    #     conn = psycopg2.connect(
    #         'dbname=slowquery host=localhost user=root password=root')
    #     cursor = conn.cursor()
    #     try:
    #         cursor.execute("select pg_sleep(1);")
    #         cursor.execute("select query from pg_stat_statements;")
    #         results = cursor.fetchall()
    #         print(results)
    #     finally:
    #         cursor.close()
    #         conn.close()
