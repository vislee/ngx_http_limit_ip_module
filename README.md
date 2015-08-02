# ngx_http_limit_ip_module #

配合日志分析系统，动态block remote ip。
对外提供查询、删除、添加规则接口。


配置

```

limit_cache_zone_size xxx;
limit_continue        xxx;

location /rule {
    limit_ip;
    allow 127.0.0.1;
    deny all;
}


if ($limit_act ~ "verify") {
	return 404;
}

if ($limit_act ~ "deny") {
	return 444;
}

```

变量

```

$limit_act
#取值：
allow, verify, deny

```


接口

```

#1. 设置规则：
http://xxx.com/rule/set?ip=xxx.xxx.xxx.xxx[&expire=100][&times=1|2]
说明：
成功返回ok
失败返回err
ip 可以是一个网段。格式：xxx.xxx.xxx.xxx,xxx 或者 xxx.xxx.xxx
如果不设置expire，取默认的有效时长，参考‘limit_continue’。
ip 可以是访问的域名。

#2. 失效规则：
http://xxx.com/rule/set?ip=xxx.xxx.xxx.xxx&expire=0
如果你确定该规则还要设置，只是暂时放开，建议调用该接口。


#3. 删除规则：
http://xxx.com/rule/del?ip=xxx.xxx.xxx.xxx


#4. 查看规则：
http://xxx.com/rule/get[?ip=xxx.xxx.xxx.xxx[&expire=1]]
说明：
如果不指定参数，dump所有生效的规则。
如果指定ip，dump该ip的规则，如果指定expire＝1，dump指定ip且生效的规则。
没有生效的规则，返回 null。

结果：
rule=10.220.39 extend=003,025 expire=1434420610 times=00001;rule=10.220.39.117 extend=000,255 expire=1434420610 times=00001;rule=10.220.39.116 extend=000,255 expire=1434420610 times=00001;rule=10.220.39.115 extend=000,255 expire=1434420610 times=00001;

结果说明：
rule 是指定的规则。extend 是规则扩展，目前只有网段在使用，表示主机号，闭区间。expire 表示有效时间。
times 是规则有效时间内规则的设置次数，该字段会影响规则的有效时长以及 $limit_act 变量的值，所以也可以在set规则时指定该值从而修改动作。

```



说明：



