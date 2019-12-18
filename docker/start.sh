#!/bin/bash
sed -e "s|#ES_URL#|$ES_URL|g" /logstash.conf.in > /logstash.conf
/bmp2txt $BMP2TXT_OPTS | /usr/share/logstash/bin/logstash -f /logstash.conf