FROM logstash:7.5.0
USER root
RUN yum install -y librdkafka
ADD bmp2txt start.sh logstash.conf.in estemplate.json /
CMD [ "/start.sh" ]
