#!/bin/bash
#######################################
#   Developed by Ajinkya Patil		  #
#   contact:-apatil@cloudera.com	  #
#######################################
if [ $# -ne 4 ]
then
        echo "Usage: $0 <cluster-name> <admin> <password> <ambari-server>"
        exit 1
fi

CLUSTER_NAME=$1
ADMIN=$2
PASSWORD=$3
AMBARI_SERVER=$4
HOST_NAME_PREFIX=`hostname -f|cut -d'-' -f1`
DOMAIN_NAME=`hostname -f|cut -d'.' -f2-`
KNOX_HOST=$HOST_NAME_PREFIX-node3.$DOMAIN_NAME
VERSION=`ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no $KNOX_HOST 'hdp-select versions' |awk 'FNR==1'`
SHORT_VER=`ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no $KNOX_HOST 'hdp-select versions' |awk 'FNR==1' | cut -b -3`
LOGS="/var/log"
get_host_copnents()
{
        echo -e "\n exporting hosts table"
        export PGPASSWORD=bigdata; psql -U ambari -c "\COPY hosts(host_id, host_name) TO '/tmp/hosts.txt';"

        echo -e "\n exporting hostcomponent table"
        export PGPASSWORD=bigdata; psql -U ambari -c "\COPY hostcomponentstate(host_id, component_name) TO '/tmp/hostcompo.txt';"

        echo -e "\n mapping host_id to hostnames"
        awk 'NR==FNR{a[$1]=$2; next}{$1=a[$1]; print}' /tmp/hosts.txt /tmp/hostcompo.txt > /tmp/hostcompmapping.txt
		sleep 30
}
get_host_copnents|tee -a $LOGS/host_comp.log
CLUSTER_NAME=`export PGPASSWORD=bigdata; psql -U ambari -c "select cluster_name from clusters;" | awk FNR==3`
SECURITY_TYPE=`export PGPASSWORD=bigdata; psql -U ambari -c "select security_type from clusters;" | awk FNR==3`
EXISTS_KNOX_HOST=`grep KNOX_GATEWAY /tmp/hostcompmapping.txt | awk 'FNR==1 {print$1}'`
NAME_NODE=`grep NAMENODE /tmp/hostcompmapping.txt | awk 'FNR==1 {print$1}'`
RANGER_ADMIN=`grep RANGER_ADMIN /tmp/hostcompmapping.txt | awk 'FNR==1 {print$1}'`
RESOURCE_MANAGER=`grep RESOURCEMANAGER /tmp/hostcompmapping.txt | awk 'FNR==1 {print$1}'`
ATLAS_SERVER=`grep ATLAS_SERVER /tmp/hostcompmapping.txt | awk 'FNR==1 {print$1}'`
HBASE_MASTER=`grep HBASE_MASTER /tmp/hostcompmapping.txt | awk 'FNR==1 {print$1}'`
HIVE_SERVER=`grep HIVE_SERVER /tmp/hostcompmapping.txt | awk 'FNR==1 {print$1}'`
AMBARI_PID=`ps -ef|grep AmbariServer|grep -v grep|awk '{print $2}'`
AMBARI_PORT=`netstat -tulapn|grep ${AMBARI_PID}|grep LISTEN|egrep -v '8440|8441'|awk '{print $4}'|rev|cut -d':' -f1|rev`
HOST_NAME_PREFIX=`hostname -f|cut -d'-' -f1`





[ -z "$RANGER_ADMIN" ] && RANGER_ADMIN="HOSTNAME_OF_RANGER"; if env | grep -q ^RANGER_ADMIN=; then :; else export RANGER_ADMIN; fi
[ -z "$ATLAS_SERVER" ] && ATLAS_SERVER="HOSTNAME_OF_ATLAS"; if env | grep -q ^ATLAS_SERVER=; then :; else export ATLAS_SERVER; fi
[ -z "$HBASE_MASTERR" ] && HBASE_MASTER="HOSTNAME_OF_HBASE"; if env | grep -q ^HBASE_MASTER=; then :; else export HBASE_MASTERR; fi
[ -z "$HIVE_SERVER" ] && HIVE_SERVER="HOSTNAME_OF_HIVESERVER2"; if env | grep -q ^HIVE_SERVER=; then :; else export HIVE_SERVER; fi
[ -z "$EXISTS_KNOX_HOST" ] && EXISTS_KNOX_HOST="NOT_INSTALLED"; if env | grep -q ^EXISTS_KNOX_HOST=; then :; else export EXISTS_KNOX_HOST; fi
if [ -n "$EXISTS_KNOX_HOST" -a "$EXISTS_KNOX_HOST" != 'NOT_INSTALLED' ]; then KNOX_HOST=$EXISTS_KNOX_HOST; fi
if grep -q "api.ssl=true" /etc/ambari-server/conf/ambari.properties; then export PROTOCOL=https; else PROTOCOL=http;fi; echo $PROTOCOL



creating_admin_creds()
{
        if [ -n "$KDOMAIN" -a "$KDOMAIN" = 'SUPPORT.COM' ]
        then
		echo -e "\n kerberos is configured with existing AD"
        cat >> /tmp/AD_creds <<-EOL 
        {
          "Credential" : {
            "principal" : "test1@SUPPORT.COM",
            "key" : "hadoop12345!",
            "type" : "temporary"
          }
        }
		EOL
        curl -k -H "X-Requested-By:ambari" -u $ADMIN:$PASSWORD -i -X POST -d @/tmp/AD_creds $PROTOCOL://$AMBARI_SERVER:$AMBARI_PORT/api/v1/clusters/`echo $CLUSTER_NAME`/credentials/kdc.admin.credential
        else
		echo -e "\n kerberos is configured with MIT KDC"
        cat >> /tmp/MIT_creds <<-EOL
        {
          "Credential" : {
            "principal" : "admin/admin@'$KDOMAIN'",
            "key" : "hadoop",
            "type" : "temporary"
          }
        }
		EOL
        curl -k -H "X-Requested-By:ambari" -u $ADMIN:$PASSWORD -i -X POST -d @/tmp/MIT_creds $PROTOCOL://$AMBARI_SERVER:$AMBARI_PORT/api/v1/clusters/`echo $CLUSTER_NAME`/credentials/kdc.admin.credential
        fi
}
kerberos_check()
{
        if [ -n "$SECURITY_TYPE" -a "$SECURITY_TYPE" = 'NONE' ]
        then
        echo -e "\n kerberos is not enabled on $CLUSTER_NAME"
        else
        curl -k -H "X-Requested-By:ambari" -u $ADMIN:$PASSWORD -i -X DELETE $PROTOCOL://$AMBARI_SERVER:$AMBARI_PORT/api/v1/clusters/`echo $CLUSTER_NAME`/credentials/kdc.admin.credential
		rm -rf /tmp/MIT_creds
		rm -rf /tmp/AD_creds
		echo -e "\n getting the realm name"
		KDOMAIN=$(export PGPASSWORD=bigdata; psql -U ambari -c "\COPY kerberos_principal(principal_name) TO '/tmp/principals.txt'"; sed -i.bak -n '1p;' /tmp/principals.txt; cat /tmp/principals.txt | cut -d '@' -f2)
		echo $KDOMAIN
		
        creating_admin_creds
        fi
}


installing_knox_packages_for_master_secret()
{

	if [ -n "$EXISTS_KNOX_HOST" -a "$EXISTS_KNOX_HOST" = 'NOT_INSTALLED' ]
	then
	 echo -e "\n installing knox package"
	 ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no $KNOX_HOST 'yum install knox -y'
	
	
	 ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no $KNOX_HOST 'hdp-select versions'
	 echo -e "\n hdp version is '$VERSION'"
	
	 echo -e "\n creating knox secret for cluster $CLUSTER_NAME and gateway.jks"
	 ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no $KNOX_HOST 'su knox -c "/usr/hdp/'$VERSION'/knox/bin/knoxcli.sh create-master --master [PROTECTED]" && su knox -c "/usr/hdp/'$VERSION'/knox/bin/knoxcli.sh create-cert --hostname '$KNOX_HOST'"'
	 
	 
	 echo -e "\n setting proxy users and hosts for knox"
	/var/lib/ambari-server/resources/scripts/configs.py --user=$ADMIN --password=$PASSWORD --port=$AMBARI_PORT --protocol=$PROTOCOL --action=set --host=$AMBARI_SERVER --cluster=`echo $CLUSTER_NAME` --config-type=core-site --key=hadoop.proxyuser.knox.hosts --value=$KNOX_HOST
	
	/var/lib/ambari-server/resources/scripts/configs.py --user=$ADMIN --password=$PASSWORD --port=$AMBARI_PORT --protocol=$PROTOCOL --action=set --host=$AMBARI_SERVER --cluster=`echo $CLUSTER_NAME` --config-type=core-site --key=hadoop.proxyuser.knox.groups --value=*
	
	/var/lib/ambari-server/resources/scripts/configs.py --user=$ADMIN --password=$PASSWORD --port=$AMBARI_PORT --protocol=$PROTOCOL --action=set --host=$AMBARI_SERVER --cluster=`echo $CLUSTER_NAME` --config-type=core-site --key=hadoop.proxyuser.HTTP.groups --value=*
	
	/var/lib/ambari-server/resources/scripts/configs.py --user=$ADMIN --password=$PASSWORD --port=$AMBARI_PORT --protocol=$PROTOCOL --action=set --host=$AMBARI_SERVER --cluster=`echo $CLUSTER_NAME` --config-type=core-site --key=hadoop.proxyuser.hdfs.groups --value=*
	
	/var/lib/ambari-server/resources/scripts/configs.py --user=$ADMIN --password=$PASSWORD --port=$AMBARI_PORT --protocol=$PROTOCOL --action=set --host=$AMBARI_SERVER --cluster=`echo $CLUSTER_NAME` --config-type=core-site --key=hadoop.proxyuser.hdfs.hosts --value=*
	
	/var/lib/ambari-server/resources/scripts/configs.py --user=$ADMIN --password=$PASSWORD --port=$AMBARI_PORT --protocol=$PROTOCOL --action=set --host=$AMBARI_SERVER --cluster=`echo $CLUSTER_NAME` --config-type=core-site --key=hadoop.proxyuser.root.hosts --value=*
	
	/var/lib/ambari-server/resources/scripts/configs.py --user=$ADMIN --password=$PASSWORD --port=$AMBARI_PORT --protocol=$PROTOCOL --action=set --host=$AMBARI_SERVER --cluster=`echo $CLUSTER_NAME` --config-type=core-site --key=hadoop.proxyuser.root.groups --value=*
	 
	 echo -e "\n`date +%Y-%m-%d,%H:%M:%S` Adding KNOX service via REST API"
	 curl -k -u $ADMIN:$PASSWORD -H "X-Requested-By:ambari"  -X POST -d '{"ServiceInfo":{"service_name":"KNOX"}}' $PROTOCOL://$AMBARI_SERVER:$AMBARI_PORT/api/v1/clusters/`echo $CLUSTER_NAME`/services
	 sleep 5

	 echo -e "\n`date +%Y-%m-%d,%H:%M:%S` Adding KNOX_GATEWAY to the KNOX service"

	 curl -k -u $ADMIN:$PASSWORD -H "X-Requested-By:ambari" -X POST $PROTOCOL://$AMBARI_SERVER:$AMBARI_PORT/api/v1/clusters/`echo $CLUSTER_NAME`/services/KNOX/components/KNOX_GATEWAY
	 
	
	echo -e "\n`date +%Y-%m-%d,%H:%M:%S` assigning KNOX_GATEWAY to HOST '$HOST_NAME_PREFIX'-node3.'$DOMAIN_NAME' "

	curl -k -u $ADMIN:$PASSWORD $PROTOCOL://$AMBARI_SERVER:$AMBARI_PORT/api/v1/clusters/`echo $CLUSTER_NAME`/hosts  -H "X-Requested-By:ambari" --data '{"RequestInfo":{"query":"Hosts/host_name='$KNOX_HOST'"},"Body":{"host_components":[{"HostRoles":{"component_name":"KNOX_GATEWAY"}}]}}'
	

	 sleep 5
	else
      :
	fi
}


configuring_core_site()
{
	
	
	echo -e "\n copying fast-hdfs-resource.jar"
	ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no $KNOX_HOST 'cp /var/lib/ambari-agent/cache/stack-hooks/before-START/files/fast-hdfs-resource.jar /var/lib/ambari-agent/lib/'
	
	echo -e "\n restarting ambari agent on host $KONX_HOST"
	ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no $KNOX_HOST 'ambari-agent restart'
	sleep 30
	
}

	

deploying_knox()
{
	

	echo -e "\n`date +%Y-%m-%d,%H:%M:%S` Creating configuration"


	sleep 5
	
	echo -e "\n creating ranger-knox-security"
	curl -k -u $ADMIN:$PASSWORD -H "X-Requested-By:ambari" -X POST -d '{"type": "ranger-knox-security", "tag": "version1", "properties" : {
	   "ranger.plugin.knox.policy.cache.dir" : "/etc/ranger/{{repo_name}}/policycache",
       "ranger.plugin.knox.policy.pollIntervalMs" : "30000",
       "ranger.plugin.knox.policy.rest.ssl.config.file" : "/usr/hdp/current/knox-server/conf/ranger-policymgr-ssl.xml",
       "ranger.plugin.knox.policy.rest.url" : "http://'$RANGER_ADMIN':6080",
       "ranger.plugin.knox.policy.source.impl" : "org.apache.ranger.admin.client.RangerAdminJersey2RESTClient",
       "ranger.plugin.knox.service.name" : "{{repo_name}}"
	  }}' $PROTOCOL://$AMBARI_SERVER:$AMBARI_PORT/api/v1/clusters/`echo $CLUSTER_NAME`/configurations

	sleep 5
	

	echo -e "\n creating ldap-log4j"
	curl -k -u $ADMIN:$PASSWORD -H "X-Requested-By:ambari" -X POST -d '{"type": "ldap-log4j", "tag": "version1",  "properties" : {
	  "content" : "\n        # Licensed to the Apache Software Foundation (ASF) under one\n        # or more contributor license agreements.  See the NOTICE file\n # distributed with this work for additional information\n        # regarding copyright ownership.  The ASF licenses this file\n        # to you under the Apache License, Version 2.0 (the\n        # \"License\"); you may not use this file except in compliance\n        # with the License.  You may obtain a copy of the License at\n        #\n        #     http://www.apache.org/licenses/LICENSE-2.0\n        #\n        # Unless required by applicable law or agreed to in writing, software\n        # distributed under the License is distributed on an \"AS IS\" BASIS,\n        # WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.\n        # See the License for the specific language governing permissions and\n        # limitations under the License.\n\n        app.log.dir=${launcher.dir}/../logs\n        app.log.file=${launcher.name}.log\n\n        log4j.rootLogger=ERROR, drfa\n        log4j.logger.org.apache.directory.server.ldap.LdapServer=INFO\n        log4j.logger.org.apache.directory=WARN\n\n        log4j.appender.stdout=org.apache.log4j.ConsoleAppender\n        log4j.appender.stdout.layout=org.apache.log4j.PatternLayout\n        log4j.appender.stdout.layout.ConversionPattern=%d{yy/MM/dd HH:mm:ss} %p %c{2}: %m%n\n\n        log4j.appender.drfa=org.apache.log4j.DailyRollingFileAppender\n        log4j.appender.drfa.File=${app.log.dir}/${app.log.file}\n        log4j.appender.drfa.DatePattern=.yyyy-MM-dd\n        log4j.appender.drfa.layout=org.apache.log4j.PatternLayout\n        log4j.appender.drfa.layout.ConversionPattern=%d{ISO8601} %-5p %c{2} (%F:%M(%L)) - %m%n\n        log4j.appender.drfa.MaxFileSize = {{knox_ldap_log_maxfilesize}}MB\n        log4j.appender.drfa.MaxBackupIndex = {{knox_ldap_log_maxbackupindex}}",
            "knox_ldap_log_maxbackupindex" : "20",
            "knox_ldap_log_maxfilesize" : "256"
	 
	  }}' $PROTOCOL://$AMBARI_SERVER:$AMBARI_PORT/api/v1/clusters/`echo $CLUSTER_NAME`/configurations

	  sleep 5
	  
	  echo -e "\n creating gateway-site"
	  curl -k -u $ADMIN:$PASSWORD -H "X-Requested-By:ambari" -X POST -d '{"type": "gateway-site", "tag": "version1", "properties" : {
	        "gateway.dispatch.whitelist" : "^.*$;^https?:(.+\\.coelab\\.cloudera\\.com):[0-9]+?.*$",
            "gateway.dispatch.whitelist.services" : "DATANODE,HBASEUI,HDFSUI,JOBHISTORYUI,NODEUI,YARNUI,knoxauth",
            "gateway.gateway.conf.dir" : "deployments",
            "gateway.hadoop.kerberos.secured" : "false",
            "gateway.knox.admin.groups" : "admin",
            "gateway.knox.admin.users" : "admin,knox.admin",
            "gateway.path" : "gateway",
            "gateway.port" : "8443",
            "gateway.read.only.override.topologies" : "admin,knoxsso,default",
            "gateway.websocket.feature.enabled" : "{{websocket_support}}",
            "java.security.auth.login.config" : " ",
            "java.security.krb5.conf" : "/etc/krb5.conf",
            "sun.security.krb5.debug" : "false",
			"java.security.auth.login.config" : "/etc/knox/conf/krb5JAASLogin.conf"
	  }}' $PROTOCOL://$AMBARI_SERVER:$AMBARI_PORT/api/v1/clusters/`echo $CLUSTER_NAME`/configurations

	sleep 5
	
	echo -e "\n creating ranger-knox-policymgr-ssl"
	curl -k -u $ADMIN:$PASSWORD -H "X-Requested-By:ambari" -X POST -d '{"type": "ranger-knox-policymgr-ssl", "tag": "version1", "properties" : {
            "xasecure.policymgr.clientssl.keystore" : " ",
            "xasecure.policymgr.clientssl.keystore.credential.file" : "jceks://file{{credential_file}}",
            "xasecure.policymgr.clientssl.keystore.password" : " ",
            "xasecure.policymgr.clientssl.truststore" : " ",
            "xasecure.policymgr.clientssl.truststore.credential.file" : "jceks://file{{credential_file}}",
            "xasecure.policymgr.clientssl.truststore.password" : " "
	}}' $PROTOCOL://$AMBARI_SERVER:$AMBARI_PORT/api/v1/clusters/`echo $CLUSTER_NAME`/configurations

	sleep 5
	
	
	echo -e "\n creating ranger-knox-plugin-properties"
	curl -k -u $ADMIN:$PASSWORD -H "X-Requested-By:ambari" -X POST -d '{"type": "ranger-knox-plugin-properties", "tag": "version1", "properties" : {
            "KNOX_HOME" : "/usr/hdp/current/knox-server",
            "REPOSITORY_CONFIG_PASSWORD" : " ",
            "REPOSITORY_CONFIG_USERNAME" : "admin",
            "common.name.for.certificate" : "",
            "external_admin_password" : "",
            "external_admin_username" : "",
            "external_ranger_admin_password" : "",
            "external_ranger_admin_username" : "",
            "policy_user" : "ambari-qa",
            "ranger-knox-plugin-enabled" : "No"
	}}' $PROTOCOL://$AMBARI_SERVER:$AMBARI_PORT/api/v1/clusters/`echo $CLUSTER_NAME`/configurations
	
	sleep 5


	echo -e "\n creating knox-env"
    curl -k -u $ADMIN:$PASSWORD -H "X-Requested-By:ambari" -X POST -d '{"type": "knox-env", "tag": "version1", "properties" : {
            "knox_group" : "knox",
			"knox_master_secret" : " ",
            "knox_pid_dir" : "/var/run/knox",
            "knox_user" : "knox",
			"knox_principal_name" : "knox/_HOST@'$KDOMAIN'"
	}}' $PROTOCOL://$AMBARI_SERVER:$AMBARI_PORT/api/v1/clusters/`echo $CLUSTER_NAME`/configurations
	
	sleep 5
  
  	echo -e "\n creating ranger-knox-audit"
    curl -k -u $ADMIN:$PASSWORD -H "X-Requested-By:ambari" -X POST -d '{"type": "ranger-knox-audit", "tag": "version1", "properties" : {
            "ranger.plugin.knox.ambari.cluster.name" : "{{cluster_name}}",
            "xasecure.audit.destination.hdfs" : "true",
            "xasecure.audit.destination.hdfs.batch.filespool.dir" : "/var/log/knox/audit/hdfs/spool",
            "xasecure.audit.destination.hdfs.dir" : "hdfs://'$NAME_NODE':8020/ranger/audit",
            "xasecure.audit.destination.solr" : "true",
            "xasecure.audit.destination.solr.batch.filespool.dir" : "/var/log/knox/audit/solr/spool",
            "xasecure.audit.destination.solr.force.use.inmemory.jaas.config" : "true",
            "xasecure.audit.destination.solr.urls" : "http://[solr_host]:8886/solr/ranger_audits_shrad1_replica1",
            "xasecure.audit.destination.solr.zookeepers" : "'$HOST_NAME_PREFIX'-node1.'$HOST_NAME_PREFIX':2181,'$HOST_NAME_PREFIX'-node2.'$DOMAIN_NAME':2181,'$HOST_NAME_PREFIX'-node3.'$DOMAIN_NAME':2181/infra-solr",
            "xasecure.audit.is.enabled" : "false",
            "xasecure.audit.jaas.Client.loginModuleControlFlag" : "required",
            "xasecure.audit.jaas.Client.loginModuleName" : "com.sun.security.auth.module.Krb5LoginModule",
            "xasecure.audit.jaas.Client.option.keyTab" : "/etc/security/keytabs/knox.service.keytab",
            "xasecure.audit.jaas.Client.option.principal" : "knox/_HOST@'$KDOMAIN'",
            "xasecure.audit.jaas.Client.option.serviceName" : "solr",
            "xasecure.audit.jaas.Client.option.storeKey" : "false",
            "xasecure.audit.jaas.Client.option.useKeyTab" : "true",
            "xasecure.audit.provider.summary.enabled" : "false"
	}}' $PROTOCOL://$AMBARI_SERVER:$AMBARI_PORT/api/v1/clusters/`echo $CLUSTER_NAME`/configurations

    sleep 5
	
	
	echo -e "\n creating gateway-log4j"
	curl -k -u $ADMIN:$PASSWORD -H "X-Requested-By:ambari" -X POST -d '{"type": "gateway-log4j", "tag": "version1", "properties" : {
             "content" : "\n\n      # Licensed to the Apache Software Foundation (ASF) under one\n      # or more contributor license agreements. See the NOTICE file\n      # distributed with this work for additional information\n      # regarding copyright ownership. The ASF licenses this file\n      # to you under the Apache License, Version 2.0 (the\n      # \"License\"); you may not use this file except in compliance\n      # with the License. You may obtain a copy of the License at\n      #\n      # http://www.apache.org/licenses/LICENSE-2.0\n      #\n      # Unless required by applicable law or agreed to in writing, software\n      # distributed under the License is distributed on an \"AS IS\" BASIS,\n      # WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.\n      # See the License for the specific language governing permissions and\n      # limitations under the License.\n\n      app.log.dir=${launcher.dir}/../logs\n      app.log.file=${launcher.name}.log\n      app.audit.file=${launcher.name}-audit.log\n\n      log4j.rootLogger=ERROR, drfa\n\n      log4j.logger.org.apache.knox.gateway=INFO\n      #log4j.logger.org.apache.knox.gateway=DEBUG\n\n      #log4j.logger.org.eclipse.jetty=DEBUG\n      #log4j.logger.org.apache.shiro=DEBUG\n      #log4j.logger.org.apache.http=DEBUG\n      #log4j.logger.org.apache.http.client=DEBUG\n      #log4j.logger.org.apache.http.headers=DEBUG\n      #log4j.logger.org.apache.http.wire=DEBUG\n\n      log4j.appender.stdout=org.apache.log4j.ConsoleAppender\n      log4j.appender.stdout.layout=org.apache.log4j.PatternLayout\n      log4j.appender.stdout.layout.ConversionPattern=%d{yy/MM/dd HH:mm:ss} %p %c{2}: %m%n\n\n      log4j.appender.drfa=org.apache.log4j.DailyRollingFileAppender\n      log4j.appender.drfa.File=${app.log.dir}/${app.log.file}\n      log4j.appender.drfa.DatePattern=.yyyy-MM-dd\n      log4j.appender.drfa.layout=org.apache.log4j.PatternLayout\n      log4j.appender.drfa.layout.ConversionPattern=%d{ISO8601} %-5p %c{2} (%F:%M(%L)) - %m%n\n      log4j.appender.drfa.MaxFileSize = {{knox_gateway_log_maxfilesize}}MB\n      log4j.appender.drfa.MaxBackupIndex = {{knox_gateway_log_maxbackupindex}}\n\n      log4j.logger.audit=INFO, auditfile\n      log4j.appender.auditfile=org.apache.log4j.DailyRollingFileAppender\n      log4j.appender.auditfile.File=${app.log.dir}/${app.audit.file}\n      log4j.appender.auditfile.Append = true\n      log4j.appender.auditfile.DatePattern = '.'yyyy-MM-dd\n      log4j.appender.auditfile.layout = org.apache.hadoop.gateway.audit.log4j.layout.AuditLayout",
            "knox_gateway_log_maxbackupindex" : "20",
            "knox_gateway_log_maxfilesize" : "256"
	}}' $PROTOCOL://$AMBARI_SERVER:$AMBARI_PORT/api/v1/clusters/`echo $CLUSTER_NAME`/configurations
	
	sleep 5
  
  	echo -e "\n creating admin-topology"
    curl -k -u $ADMIN:$PASSWORD -H "X-Requested-By:ambari" -X POST -d '{"type": "admin-topology", "tag": "version1", "properties" : {
             "content" : "\n    <topology>\n\n        <gateway>\n\n             <provider>\n                <role>authentication</role>\n                <name>ShiroProvider</name>\n                <enabled>true</enabled>\n                <param>\n                    <name>sessionTimeout</name>\n                    <value>30</value>\n                </param>\n                <param>\n                    <name>main.ldapRealm</name>\n                    <value>org.apache.hadoop.gateway.shirorealm.KnoxLdapRealm</value>\n                </param>\n                               <!-- changes for AD/user sync -->\n\n<param>\n    <name>main.ldapContextFactory</name>\n    <value>org.apache.hadoop.gateway.shirorealm.KnoxLdapContextFactory</value>\n</param>\n\n<!-- main.ldapRealm.contextFactory needs to be placed before other main.ldapRealm.contextFactory* entries  -->\n<param>\n    <name>main.ldapRealm.contextFactory</name>\n    <value>$ldapContextFactory</value>\n</param>\n\n<!-- AD url -->\n<param>\n    <name>main.ldapRealm.contextFactory.url</name>\n    <value>ldap://ad01.support.com:389</value> \n</param>\n\n<!-- system user -->\n<param>\n    <name>main.ldapRealm.contextFactory.systemUsername</name>\n    <value>cn=test1,ou=hortonworks,dc=support,dc=comt</value>\n</param>\n\n<!-- pass in the password using the alias created earlier -->\n<param>\n    <name>main.ldapRealm.contextFactory.systemPassword</name>\n    <value>hadoop12345!</value>\n</param>\n\n                    <param>\n                        <name>main.ldapRealm.contextFactory.authenticationMechanism</name>\n                        <value>simple</value>\n                    </param>\n                    <param>\n                        <name>urls./**</name>\n                        <value>authcBasic</value> \n                    </param>\n\n<!--  AD groups of users to allow -->\n<param>\n    <name>main.ldapRealm.searchBase</name>\n    <value>OU=squadron_users,OU=users,OU=hortonworks,DC=SUPPORT,DC=COM</value>\n</param>\n<param>\n    <name>main.ldapRealm.userObjectClass</name>\n    <value>person</value>\n</param>\n<param>\n    <name>main.ldapRealm.userSearchAttributeName</name>\n    <value>sAMAccountName</value>\n</param>\n\n<!-- changes needed for group sync-->\n<param>\n    <name>main.ldapRealm.authorizationEnabled</name>\n    <value>true</value>\n</param>\n<param>\n    <name>main.ldapRealm.groupSearchBase</name>\n    <value>OU=squadron_users,OU=users,OU=hortonworks,DC=SUPPORT,DC=COM</value>\n</param>\n<param>\n    <name>main.ldapRealm.groupObjectClass</name>\n    <value>group</value>\n</param>\n<param>\n    <name>main.ldapRealm.groupIdAttribute</name>\n    <value>cn</value>\n</param>\n\n            <provider>\n                <role>authorization</role>\n                <name>AclsAuthz</name>\n                <enabled>true</enabled>\n                <param>\n\t               <name>knox.acl.mode</name>\n\t               <value>OR</value>\n                   </param>\n                <param>\n                    <name>knox.acl</name>\n                    <value>KNOX_ADMIN_USERS;KNOX_ADMIN_GROUPS;*</value>\n                </param>\n            </provider>\n\n            <provider>\n                <role>identity-assertion</role>\n                <name>HadoopGroupProvider</name>\n                <enabled>true</enabled>\n                <param>\n                    <name>CENTRAL_GROUP_CONFIG_PREFIX</name>\n                    <value>gateway.group.config.</value>\n                </param>\n            </provider>\n\n    </provider>\n\n    </gateway>\n\n        <service>\n            <role>KNOX</role>\n        </service>\n\n    </topology>"
	}}' $PROTOCOL://$AMBARI_SERVER:$AMBARI_PORT/api/v1/clusters/`echo $CLUSTER_NAME`/configurations
	
	sleep 5
	
	echo -e "\n creating topology"
	curl -k -u $ADMIN:$PASSWORD -H "X-Requested-By:ambari"  -X POST -d '{"type": "topology", "tag": "version1", "properties" : {
             "content" : "<topology>\n\n            <gateway>\n\n                <provider>\n                    <role>authentication</role>\n                    <name>ShiroProvider</name>\n                    <enabled>true</enabled>\n                    <param>\n                        <name>sessionTimeout</name>\n                        <value>30</value>\n                    </param>\n                    <param>\n                        <name>main.ldapRealm</name>\n                        <value>org.apache.hadoop.gateway.shirorealm.KnoxLdapRealm</value> \n                    </param>\n\n\n\n<param>\n    <name>main.ldapContextFactory</name>\n    <value>org.apache.hadoop.gateway.shirorealm.KnoxLdapContextFactory</value>\n</param>\n\n\n<param>\n    <name>main.ldapRealm.contextFactory</name>\n    <value>$ldapContextFactory</value>\n</param>\n\n\n<param>\n    <name>main.ldapRealm.contextFactory.url</name>\n    <value>ldap://ad01.support.com:389</value>\n</param>\n\n\n<param>\n    <name>main.ldapRealm.contextFactory.systemUsername</name>\n    <value>cn=test1,ou=hortonworks,dc=support,dc=com</value>\n</param>\n\n\n<param>\n    <name>main.ldapRealm.contextFactory.systemPassword</name>\n    <value>hadoop12345!</value>\n</param>\n\n                    <param>\n                        <name>main.ldapRealm.contextFactory.authenticationMechanism</name>\n                        <value>simple</value>\n                    </param>\n                    <param>\n                        <name>urls./**</name>\n                        <value>authcBasic</value> \n                    </param>\n\n\n<param>\n    <name>main.ldapRealm.searchBase</name>\n    <value>OU=squadron_users,OU=users,OU=hortonworks,DC=SUPPORT,DC=COM</value>\n</param>\n<param>\n    <name>main.ldapRealm.userObjectClass</name>\n    <value>person</value>\n</param>\n<param>\n    <name>main.ldapRealm.userSearchAttributeName</name>\n    <value>sAMAccountName</value>\n</param>\n\n\n<param>\n    <name>main.ldapRealm.authorizationEnabled</name>\n    <value>true</value>\n</param>\n<param>\n    <name>main.ldapRealm.groupSearchBase</name>\n    <value>OU=squadron_users,OU=users,OU=hortonworks,DC=SUPPORT,DC=COM</value>\n</param>\n<param>\n    <name>main.ldapRealm.groupObjectClass</name>\n    <value>group</value>\n</param>\n<param>\n    <name>main.ldapRealm.groupIdAttribute</name>\n    <value>cn</value>\n</param>\n\n\n                </provider>\n\n                <provider>\n                    <role>identity-assertion</role>\n                    <name>Default</name>\n                    <enabled>true</enabled>\n                </provider>\n\n                <provider>\n                    <role>authorization</role>\n                    <name>AclsAuthz</name>\n                    <enabled>true</enabled>\n                </provider>\n\n\n<provider>\n     <role>ha</role>\n     <name>HaProvider</name>\n     <enabled>true</enabled>\n     <param>\n         <name>OOZIE</name>\n         <value>maxFailoverAttempts=3;failoverSleep=1000;enabled=true</value>\n     </param>\n     <param>\n         <name>HBASE</name>\n         <value>maxFailoverAttempts=3;failoverSleep=1000;enabled=true</value>\n     </param>\n     <param>\n         <name>WEBHCAT</name>\n         <value>maxFailoverAttempts=3;failoverSleep=1000;enabled=true</value>\n     </param>\n     <param>\n         <name>WEBHDFS</name>\n         <value>maxFailoverAttempts=3;failoverSleep=1000;maxRetryAttempts=300;retrySleep=1000;enabled=true</value>\n     </param>\n     <param>\n        <name>HIVE</name>\n        <value>maxFailoverAttempts=3;failoverSleep=1000;enabled=true;zookeeperEnsemble='$HOST_NAME_PREFIX-node2.$DOMAIN_NAME':2181,'$HOST_NAME_PREFIX-node3.$DOMAIN_NAME':2181,'$HOST_NAME_PREFIX-node4.$DOMAIN_NAME':2181;\n       zookeeperNamespace=hiveserver2</value>\n     </param>\n</provider>\n\n\n\n            </gateway>\n\n    <service>\n        <role>ATLAS</role>\n        <url>http://'$ATLAS_SERVER':21000</url>\n    </service>\n\n    <service>\n        <role>ATLAS-API</role>\n        <url>http://'$ATLAS_SERVER':21000</url>\n    </service>\n\n    <service>\n        <role>HBASEUI</role>\n        <url>http://'$HBASE_MASTER':16010</url>\n    </service>\n\n<service>\n        <role>HDFSUI</role>\n        <url>http://'$NAME_NODE':50070</url>\n    </service>\n\n    <service>\n        <role>HIVE</role>\n        <url>http://'$HIVE_SERVER':10001/cliservice</url>\n    </service>\n\n    <service>\n        <role>RANGERUI</role>\n        <url>http://'$RANGER_ADMIN':6080</url>\n    </service>\n\n<service>\n        <role>RANGER</role>\n        <url>http://'$RANGER_ADMIN':6080</url>\n    </service>\n\n\n\n\n            <service>\n                <role>NAMENODE</role>\n                <url>hdfs://'$NAME_NODE':8020</url>\n            </service>\n\n            <service>\n                <role>JOBTRACKER</role>\n                <url>rpc://{{rm_host}}:{{jt_rpc_port}}</url>\n            </service>\n\n            <service>\n                <role>WEBHDFS</role>\n               <url>http://'$NAME_NODE':50070/webhdfs</url>\n            </service>\n\n            <service>\n                <role>WEBHCAT</role>\n                <url>http://{{webhcat_server_host}}:{{templeton_port}}/templeton</url>\n            </service>\n\n            <service>\n                <role>OOZIE</role>\n                <url>http://{{oozie_server_host}}:{{oozie_server_port}}/oozie</url>\n            </service>\n\n            <service>\n                <role>OOZIEUI</role>\n                <url>http://{{oozie_server_host}}:{{oozie_server_port}}/oozie/</url>\n            </service>\n\n\n            <service>\n                <role>WEBHBASE</role>\n                <url>http://{{hbase_master_host}}:{{hbase_master_port}}</url>\n            </service>\n\n            <service>\n                <role>HIVE</role>\n                <url>http://{{hive_server_host}}:{{hive_http_port}}/{{hive_http_path}}</url>\n            </service>\n            <service>\n                <role>YARNUI</role>\n                <url>http://'$RESOURCE_MANAGER':8088</url>\n            </service>\n            <service>\n                 <role>YARNUIV2</role>\n                 <url>http://'$RESOURCE_MANAGER':8088</url>\n            </service>\n\n            <service>\n                <role>RESOURCEMANAGER</role>\n                <url>http://'$RESOURCE_MANAGER':8088/ws</url>\n            </service>\n\n            <service>\n                <role>DRUID-COORDINATOR-UI</role>\n                {{druid_coordinator_urls}}\n            </service>\n\n            <service>\n                <role>DRUID-COORDINATOR</role>\n                {{druid_coordinator_urls}}\n            </service>\n\n            <service>\n                <role>DRUID-OVERLORD-UI</role>\n                {{druid_overlord_urls}}\n            </service>\n\n             <service>\n                <role>DRUID-OVERLORD</role>\n                {{druid_overlord_urls}}\n            </service>\n\n            <service>\n                <role>DRUID-ROUTER</role>\n                {{druid_router_urls}}\n            </service>\n\n            <service>\n                 <role>DRUID-BROKER</role>\n                {{druid_broker_urls}}\n            </service>\n\n            <service>\n                <role>ZEPPELINUI</role>\n                {{zeppelin_ui_urls}}\n            </service>\n\n            <service>\n                <role>ZEPPELINWS</role>\n                {{zeppelin_ws_urls}}\n            </service>\n\n        </topology>"
	}}' $PROTOCOL://$AMBARI_SERVER:$AMBARI_PORT/api/v1/clusters/`echo $CLUSTER_NAME`/configurations
	
	sleep 5
	
	echo -e "\n creating knoxsso-topology"
	curl -k -u $ADMIN:$PASSWORD -H "X-Requested-By:ambari" -X POST -d '{"type": "knoxsso-topology", "tag": "version1", "properties" : {
             "content" : "<topology>\n          <gateway>\n              <provider>\n                  <role>webappsec</role>\n                  <name>WebAppSec</name>\n                  <enabled>true</enabled>\n                  <param><name>xframe.options.enabled</name><value>true</value>\n  </param>\n              </provider>\n\n              <provider>\n                  <role>authentication</role>\n                  <name>ShiroProvider</name>\n                  <enabled>true</enabled>\n                  <param>\n                      <name>sessionTimeout</name>\n                      <value>1</value>\n                  </param>\n                  <param>\n                      <name>redirectToUrl</name>\n                      <value>/gateway/knoxsso/knoxauth/login.html</value>\n                  </param>\n                  <param>\n                      <name>restrictedCookies</name>\n                      <value>rememberme,WWW-Authenticate</value>\n                  </param>\n                  <param>\n                <name>main.ldapRealm</name>\n                <value>org.apache.hadoop.gateway.shirorealm.KnoxLdapRealm</value>\n            </param>\n            <param>\n                <name>main.ldapContextFactory</name>\n                <value>org.apache.hadoop.gateway.shirorealm.KnoxLdapContextFactory</value>\n            </param>\n            <param>\n                <name>main.ldapRealm.contextFactory</name>\n                <value>$ldapContextFactory</value>\n            </param>\n            <param>\n                <name>main.ldapRealm.contextFactory.url</name>\n                <value>ldap://ad01.support.com:389</value>\n            </param>\n            <param>\n                <name>main.ldapRealm.contextFactory.systemUsername</name>\n                <value>cn=test1,ou=hortonworks,dc=support,dc=com</value>\n            </param>\n            <param>\n                <name>main.ldapRealm.contextFactory.systemPassword</name>\n                <value>hadoop12345!</value>\n            </param>\n            <param>\n                <name>main.ldapRealm.contextFactory.authenticationMechanism</name>\n                <value>simple</value>\n            </param>\n            <param>\n                <name>urls./**</name>\n                <value>authcBasic</value>\n            </param>\n            <param>\n                <name>main.ldapRealm.userObjectClass</name>\n                <value>person</value>\n            </param>\n            <param>\n                <name>main.ldapRealm.userSearchAttributeName</name>\n                <value>sAMAccountName</value>\n            </param>\n            <param>\n                <name>main.ldapRealm.userSearchBase</name>\n                <value>OU=squadron_users,OU=users,OU=hortonworks,DC=SUPPORT,DC=COM</value>\n            </param>\n            <param>\n                <name>main.ldapRealm.authorizationEnabled</name>\n                <value>false</value>\n            </param>\n            <param>\n                <name>main.ldapRealm.groupSearchBase</name>\n                <value>OU=squadron_users,OU=users,OU=hortonworks,DC=SUPPORT,DC=COM</value>\n            </param>\n            <param>\n                <name>main.ldapRealm.groupObjectClass</name>\n                <value>group</value>\n            </param>\n            <param>\n                <name>main.ldapRealm.groupIdAttribute</name>\n                <value>cn</value>\n            </param>\n\n              </provider>\n              <provider>\n                  <role>identity-assertion</role>\n                  <name>Default</name>\n                  <enabled>true</enabled>\n              </provider>\n          </gateway>\n\n          <application>\n            <name>knoxauth</name>\n          </application>\n\n          <service>\n              <role>KNOXSSO</role>\n              <param>\n                  <name>knoxsso.cookie.secure.only</name>\n                  <value>false</value>\n              </param>\n              <param>\n                  <name>knoxsso.token.ttl</name>\n                  <value>30000</value>\n              </param>\n\n              <param>\n                 <name>knoxsso.redirect.whitelist.regex</name>\n                 <value>^.*$;^https?:(.+\\.coelab\\.cloudera\\.com):[0-9]+?.*$</value>\n              </param>\n          </service>\n\n\n\n\n      </topology>"
	}}' $PROTOCOL://$AMBARI_SERVER:$AMBARI_PORT/api/v1/clusters/`echo $CLUSTER_NAME`/configurations
	
	sleep 5
	
	echo -e "\n creating users-ldif"
	curl -k -u $ADMIN:$PASSWORD -H "X-Requested-By:ambari" -X POST -d '{"type": "users-ldif", "tag": "version1", "properties" : {
              "content" : "\n# Licensed to the Apache Software Foundation (ASF) under one\n# or more contributor license agreements.  See the NOTICE file\n# distributed with this work for additional information\n# regarding copyright ownership.  The ASF licenses this file\n# to you under the Apache License, Version 2.0 (the\n# \"License\"); you may not use this file except in compliance\n# with the License.  You may obtain a copy of the License at\n#\n#     http://www.apache.org/licenses/LICENSE-2.0\n#\n# Unless required by applicable law or agreed to in writing, software\n# distributed under the License is distributed on an \"AS IS\" BASIS,\n# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.\n# See the License for the specific language governing permissions and\n# limitations under the License.\n\nversion: 1\n\n# Please replace with site specific values\ndn: dc=hadoop,dc=apache,dc=org\nobjectclass: organization\nobjectclass: dcObject\no: Hadoop\ndc: hadoop\n\n# Entry for a sample people container\n# Please replace with site specific values\ndn: ou=people,dc=hadoop,dc=apache,dc=org\nobjectclass:top\nobjectclass:organizationalUnit\nou: people\n\n# Entry for a sample end user\n# Please replace with site specific values\ndn: uid=guest,ou=people,dc=hadoop,dc=apache,dc=org\nobjectclass:top\nobjectclass:person\nobjectclass:organizationalPerson\nobjectclass:inetOrgPerson\ncn: Guest\nsn: User\nuid: guest\nuserPassword:guest-password\n\n# entry for sample user admin\ndn: uid=admin,ou=people,dc=hadoop,dc=apache,dc=org\nobjectclass:top\nobjectclass:person\nobjectclass:organizationalPerson\nobjectclass:inetOrgPerson\ncn: Admin\nsn: Admin\nuid: admin\nuserPassword:admin-password\n\n# entry for sample user sam\ndn: uid=sam,ou=people,dc=hadoop,dc=apache,dc=org\nobjectclass:top\nobjectclass:person\nobjectclass:organizationalPerson\nobjectclass:inetOrgPerson\ncn: sam\nsn: sam\nuid: sam\nuserPassword:sam-password\n\n# entry for sample user tom\ndn: uid=tom,ou=people,dc=hadoop,dc=apache,dc=org\nobjectclass:top\nobjectclass:person\nobjectclass:organizationalPerson\nobjectclass:inetOrgPerson\ncn: tom\nsn: tom\nuid: tom\nuserPassword:tom-password\n\n# create FIRST Level groups branch\ndn: ou=groups,dc=hadoop,dc=apache,dc=org\nobjectclass:top\nobjectclass:organizationalUnit\nou: groups\ndescription: generic groups branch\n\n# create the analyst group under groups\ndn: cn=analyst,ou=groups,dc=hadoop,dc=apache,dc=org\nobjectclass:top\nobjectclass: groupofnames\ncn: analyst\ndescription:analyst  group\nmember: uid=sam,ou=people,dc=hadoop,dc=apache,dc=org\nmember: uid=tom,ou=people,dc=hadoop,dc=apache,dc=org\n\n\n# create the scientist group under groups\ndn: cn=scientist,ou=groups,dc=hadoop,dc=apache,dc=org\nobjectclass:top\nobjectclass: groupofnames\ncn: scientist\ndescription: scientist group\nmember: uid=sam,ou=people,dc=hadoop,dc=apache,dc=org\n\n# create the admin group under groups\ndn: cn=admin,ou=groups,dc=hadoop,dc=apache,dc=org\nobjectclass:top\nobjectclass: groupofnames\ncn: admin\ndescription: admin group\nmember: uid=admin,ou=people,dc=hadoop,dc=apache,dc=org"
	}}' $PROTOCOL://$AMBARI_SERVER:$AMBARI_PORT/api/v1/clusters/`echo $CLUSTER_NAME`/configurations
	
	sleep 5


	echo -e "\n `date +%Y-%m-%d,%H:%M:%S` Applying Knox configs to the cluster"
	
	echo -e "\n applying admin-topology"
	curl -k  -u $ADMIN:$PASSWORD -H "X-Requested-By:ambari" -X PUT -d '{ "Clusters" : {"desired_configs": {"type": "admin-topology", "tag" : "version1" }}}'  $PROTOCOL://$AMBARI_SERVER:$AMBARI_PORT/api/v1/clusters/`echo $CLUSTER_NAME`
	
    echo -e "\n applying gateway-log4j"
	curl -k -u $ADMIN:$PASSWORD -H "X-Requested-By:ambari" -X PUT -d '{ "Clusters" : {"desired_configs": {"type": "gateway-log4j", "tag" : "version1" }}}'  $PROTOCOL://$AMBARI_SERVER:$AMBARI_PORT/api/v1/clusters/`echo $CLUSTER_NAME`

	echo -e "\n applying gateway-site"
	curl -k -u $ADMIN:$PASSWORD -H "X-Requested-By:ambari" -X PUT -d '{ "Clusters" : {"desired_configs": {"type": "gateway-site", "tag" : "version1" }}}'  $PROTOCOL://$AMBARI_SERVER:$AMBARI_PORT/api/v1/clusters/`echo $CLUSTER_NAME`

    echo -e "\n applying knox-env"
	curl -k -u $ADMIN:$PASSWORD -H "X-Requested-By:ambari"  -X PUT -d '{ "Clusters" : {"desired_configs": {"type": "knox-env", "tag" : "version1" }}}'  $PROTOCOL://$AMBARI_SERVER:$AMBARI_PORT/api/v1/clusters/`echo $CLUSTER_NAME`

    echo -e "\n applying knoxsso-topology"
	curl -k -u $ADMIN:$PASSWORD -H "X-Requested-By:ambari" -X PUT -d '{ "Clusters" : {"desired_configs": {"type": "knoxsso-topology", "tag" : "version1" }}}'  $PROTOCOL://$AMBARI_SERVER:$AMBARI_PORT/api/v1/clusters/`echo $CLUSTER_NAME`

    echo -e "\n applying ranger-knox-audit"
	curl -k -u $ADMIN:$PASSWORD -H "X-Requested-By:ambari" -X PUT -d '{ "Clusters" : {"desired_configs": {"type": "ranger-knox-audit", "tag" : "version1" }}}'  $PROTOCOL://$AMBARI_SERVER:$AMBARI_PORT/api/v1/clusters/`echo $CLUSTER_NAME`
	
    echo -e "\n applying ranger-knox-plugin-properties"	
	curl -k -u $ADMIN:$PASSWORD -H "X-Requested-By:ambari" -X PUT -d '{ "Clusters" : {"desired_configs": {"type": "ranger-knox-plugin-properties", "tag" : "version1" }}}'  http://$AMBARI_SERVER:$AMBARI_PORT/api/v1/clusters/`echo $CLUSTER_NAME`
	
    echo -e "\n applying ranger-knox-policymgr-ssl"	
	curl -k -u $ADMIN:$PASSWORD -H "X-Requested-By:ambari" -X PUT -d '{ "Clusters" : {"desired_configs": {"type": "ranger-knox-policymgr-ssl", "tag" : "version1" }}}'  $PROTOCOL://$AMBARI_SERVER:$AMBARI_PORT/api/v1/clusters/`echo $CLUSTER_NAME`
	
	echo -e "\n applying ranger-knox-security"
	curl -k -u $ADMIN:$PASSWORD -H "X-Requested-By:ambari" -X PUT -d '{ "Clusters" : {"desired_configs": {"type": "ranger-knox-security", "tag" : "version1" }}}'  $PROTOCOL://$AMBARI_SERVER:$AMBARI_PORT/api/v1/clusters/`echo $CLUSTER_NAME`

    echo -e "\n applying topology"
	curl -k -u $ADMIN:$PASSWORD -H "X-Requested-By:ambari"  -X PUT -d '{ "Clusters" : {"desired_configs": {"type": "topology", "tag" : "version1" }}}'  $PROTOCOL://$AMBARI_SERVER:$AMBARI_PORT/api/v1/clusters/`echo $CLUSTER_NAME`

    echo -e "\n applying users-ldif"
    curl -k  -u $ADMIN:$PASSWORD -H "X-Requested-By:ambari"  -X PUT -d '{ "Clusters" : {"desired_configs": {"type": "users-ldif", "tag" : "version1" }}}'  $PROTOCOL://$AMBARI_SERVER:$AMBARI_PORT/api/v1/clusters/`echo $CLUSTER_NAME`
	
	echo -e "\n applying ldap-log4j"
	curl -k -u $ADMIN:$PASSWORD -H "X-Requested-By:ambari"  -X PUT -d '{ "Clusters" : {"desired_configs": {"type": "ldap-log4j", "tag" : "version1" }}}'  $PROTOCOL://$AMBARI_SERVER:$AMBARI_PORT/api/v1/clusters/`echo $CLUSTER_NAME`
	sleep 5



	if [ -n "$EXISTS_KNOX_HOST" -a "$EXISTS_KNOX_HOST" = 'NOT_INSTALLED' ]
	then
	echo -e "\n`date +%Y-%m-%d,%H:%M:%S` adding knox to $CLUSETR_NAME"


	curl -k -u $ADMIN:$PASSWORD -H "X-Requested-By:ambari"  -X PUT -d '{"RequestInfo": {"context" :"adding knox"}, "ServiceInfo": {"state" : "INSTALLED"}}'  $PROTOCOL://$AMBARI_SERVER:$AMBARI_PORT/api/v1/clusters/`echo $CLUSTER_NAME`/services/KNOX
	
	sleep 60

	
	curl -k -u $ADMIN:$PASSWORD -H "X-Requested-By:ambari"  -X PUT -d '{"RequestInfo": {"context" :"Starting knox"},"ServiceInfo": {"state" : "STARTED"}}'  $PROTOCOL://$AMBARI_SERVER:$AMBARI_PORT/api/v1/clusters/`echo $CLUSTER_NAME`/services/KNOX
	else
	:
	fi
	

}

knox_configuration_for_hdp()
{

	echo -e "\n chnaging yarn quicklinks and poinnintg them to knox proxy"
	
	cat << EOF > /var/lib/ambari-server/resources/stacks/HDP/$SHORT_VER/services/YARN/quicklinks.json
{
  "name": "default",
  "description": "default quick links configuration",
  "configuration": {
    "protocol":
    {
      "type": "HTTPS_ONLY"
    },
    "links": [
      {
        "name": "resourcemanager_ui",
        "label": "ResourceManager UI",
        "requires_user_name": "false",
        "component_name": "KNOX_GATEWAY",
        "url": "%@://%@:%@/gateway/hdp_ui/yarnuiv2/",
        "port": {
          "https_property": "gateway.port",
          "https_default_port": "8443",
          "regex": "^(\\d+)$",
          "site": "gateway-site"
        }
      },
      {
        "name": "resourcemanager_logs",
        "label": "ResourceManager logs",
        "requires_user_name": "false",
        "component_name": "KNOX_GATEWAY",
        "url": "%@://%@:%@/gateway/hdp_ui/yarn/logs",
        "port": {
          "https_property": "gateway.port",
          "https_default_port": "8443",
          "regex": "^(\\d+)$",
          "site": "gateway-site"
        }
      },
      {
        "name": "resourcemanager_jmx",
        "label":"ResourceManager JMX",
        "requires_user_name": "false",
        "component_name": "KNOX_GATEWAY",
        "url":"%@://%@:%@/gateway/hdp_ui/yarn/jmx",
        "port": {
          "https_property": "gateway.port",
          "https_default_port": "8443",
          "regex": "^(\\d+)$",
          "site": "gateway-site"
        }
      },
      {
        "name": "thread_stacks",
        "label":"Thread Stacks",
        "requires_user_name": "false",
        "component_name": "KNOX_GATEWAY",
        "url":"%@://%@:%@/gateway/hdp_ui/yarn/stacks",
        "port": {
          "https_property": "gateway.port",
          "https_default_port": "8443",
          "regex": "^(\\d+)$",
          "site": "gateway-site"
        }
      }
    ]
  }
}
EOF


	echo -e "\n exporting knox cert to /usr/hdp/$VERSION/knox/data/security/keystores/gateway-identity.pem "
	
	ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no $KNOX_HOST 'su knox -c "/usr/hdp/'$VERSION'/knox/bin/knoxcli.sh export-cert"'
	
	echo -e "\n copying certs to all hosts"
	scp -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no $KNOX_HOST:/usr/hdp/$VERSION/knox/data/security/keystores/gateway-identity.pem /root && scp -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no /root/gateway-identity.pem $HOST_NAME_PREFIX-node2.$DOMAIN_NAME:/root && scp -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no /root/gateway-identity.pem $HOST_NAME_PREFIX-node3.$DOMAIN_NAME:/root && scp -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no /root/gateway-identity.pem $HOST_NAME_PREFIX-node4.$DOMAIN_NAME:/root
	
	
	echo -e "\n check if ranger is installed and enabling sso for ranger"
	
	if [ -n "$RANGER_ADMIN" -a "$RANGER_ADMIN" = 'HOSTNAME_OF_RANGER' ]
	then
	 :
	else
	KNOX_CERT=`cat /root/gateway-identity.pem | tr -d '\r\n'| sed 's/-----BEGIN CERTIFICATE-----//;s/-----END CERTIFICATE-----//;/^$/d'`
	
	/var/lib/ambari-server/resources/scripts/configs.py --user=$ADMIN --password=$PASSWORD --port=$AMBARI_PORT --protocol=$PROTOCOL --action=set --host=$AMBARI_SERVER --cluster=`echo $CLUSTER_NAME` --config-type=ranger-admin-site --key=ranger.sso.enabled --value=true 
	
	/var/lib/ambari-server/resources/scripts/configs.py --user=$ADMIN --password=$PASSWORD --port=$AMBARI_PORT --protocol=$PROTOCOL --action=set --host=$AMBARI_SERVER --cluster=`echo $CLUSTER_NAME` --config-type=ranger-admin-site --key=ranger.sso.providerurl --value=https://$KNOX_HOST:8443/gateway/knoxsso/api/v1/websso 
	
	/var/lib/ambari-server/resources/scripts/configs.py --user=$ADMIN --password=$PASSWORD --port=$AMBARI_PORT --protocol=$PROTOCOL --action=set --host=$AMBARI_SERVER --cluster=`echo $CLUSTER_NAME` --config-type=ranger-admin-site --key=ranger.sso.publicKey --value=$KNOX_CERT 
	fi
	
	
	echo -e "\n check if atlas is installed and enabling sso for atlas"
	
	if [ -n "$ATLAS_SERVER" -a "$ATLAS_SERVER" = 'HOSTNAME_OF_ATLAS' ]
	then
	 :
	else
	KNOX_CERT=`cat /root/gateway-identity.pem | tr -d '\r\n'| sed 's/-----BEGIN CERTIFICATE-----//;s/-----END CERTIFICATE-----//;/^$/d'`
	
	/var/lib/ambari-server/resources/scripts/configs.py --user=$ADMIN --password=$PASSWORD --port=$AMBARI_PORT --protocol=$PROTOCOL --action=set --host=$AMBARI_SERVER --cluster=`echo $CLUSTER_NAME` --config-type=application-properties --key=atlas.sso.knox.enabled --value=true 
	
	/var/lib/ambari-server/resources/scripts/configs.py --user=$ADMIN --password=$PASSWORD --port=$AMBARI_PORT --protocol=$PROTOCOL --action=set --host=$AMBARI_SERVER --cluster=`echo $CLUSTER_NAME` --config-type=application-properties --key=atlas.sso.knox.providerurl --value=https://$KNOX_HOST:8443/gateway/knoxsso/api/v1/websso 
	
	/var/lib/ambari-server/resources/scripts/configs.py --user=$ADMIN --password=$PASSWORD --port=$AMBARI_PORT --protocol=$PROTOCOL --action=set --host=$AMBARI_SERVER --cluster=`echo $CLUSTER_NAME` --config-type=application-properties --key=atlas.sso.knox.publicKey --value=$KNOX_CERT
	
	/var/lib/ambari-server/resources/scripts/configs.py --user=$ADMIN --password=$PASSWORD --port=$AMBARI_PORT --protocol=$PROTOCOL --action=set --host=$AMBARI_SERVER --cluster=`echo $CLUSTER_NAME` --config-type=application-properties --key=atlas.sso.knox.browser.useragent --value=Mozilla,chrome 
	fi  
	
	echo -e "\n removing output files of configs.py"
	
	rm -rf /root/doSet_version*

	
	echo -e "\n restarting all required services"
	
	curl -k  -u $ADMIN:$PASSWORD -H "X-Requested-By:ambari" -X POST -H "X-Requested-By:ambari" -X POST -d '{"RequestInfo":{"command":"RESTART","context":"Restart All Required services after knox installation","operation_level":"host_component"},"Requests/resource_filters":[{"hosts_predicate":"HostRoles/stale_configs=true&HostRoles/cluster_name='`echo $CLUSTER_NAME`'"}]}' $PROTOCOL://$AMBARI_SERVER:$AMBARI_PORT/api/v1/clusters/`echo $CLUSTER_NAME`/requests
	
	


}

kerberos_check|tee -a $LOGS/krbchk.log
installing_knox_packages_for_master_secret|tee -a $LOGS/install.log
configuring_core_site|tee -a $LOGS/core-site.log
deploying_knox|tee -a $LOGS/knox_deploy.log
knox_configuration_for_hdp| tee -a $LOGS/knox_configuration_for_hdp.log


