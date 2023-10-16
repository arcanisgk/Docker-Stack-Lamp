FROM mysql:latest

RUN echo '[client]' >> /etc/mysql/my.cnf
RUN echo 'local_infile=1' >> /etc/mysql/my.cnf

RUN echo '[mysqld]' >> /etc/mysql/my.cnf
RUN echo 'default-authentication-plugin=mysql_native_password' >> /etc/mysql/my.cnf
RUN echo 'local-infile=1' >> /etc/mysql/my.cnf
RUN echo 'sql_mode="ERROR_FOR_DIVISION_BY_ZERO,ALLOW_INVALID_DATES"' >> /etc/mysql/my.cnf
RUN echo 'innodb_log_buffer_size=256M' >> /etc/mysql/my.cnf
RUN echo 'bulk_insert_buffer_size=4G' >> /etc/mysql/my.cnf
RUN echo 'innodb_buffer_pool_size=4G' >> /etc/mysql/my.cnf
RUN echo 'innodb_change_buffer_max_size=1' >> /etc/mysql/my.cnf
RUN echo 'information_schema_stats_expiry=0' >> /etc/mysql/my.cnf