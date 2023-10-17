FROM php:8.1-apache-bullseye

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update &&  \
    apt-get upgrade -y --no-install-recommends --fix-missing

RUN apt-get install -y --no-install-recommends --fix-missing tzdata sed build-essential dialog nano apt-utils cron wget git curl zip openssl gettext-base

RUN apt-get -y autoremove && \
    apt-get clean

RUN a2enmod proxy
RUN a2enmod proxy_http
RUN a2enmod rewrite
RUN a2enmod headers

RUN service apache2 restart

RUN mkdir -p /var/log/cron && \
    chmod 755 /var/log/cron

CMD cat /etc/cron-task/new-task >> /etc/cron.d/cron-task && \
    chmod 0644 /etc/cron.d/cron-task && \
    touch /var/log/cron/cron.log && \
    cron && \
    chmod +x /etc/cron-task/crontab-ui.sh && \
    /etc/cron-task/crontab-ui.sh && \
    /usr/local/bin/apache2-foreground && \
    tail -f /var/log/cron/cron.log