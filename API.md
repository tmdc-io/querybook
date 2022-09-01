## Create Metastore
```shell
curl --location --request POST 'http://127.0.0.1:10001/querybook/ds/admin/query_metastore/' \
--header 'Origin: http://google.com' \
--header 'Authorization: Bearer YXRsYXNfNDBkMTMwMDY4NTM4OTM3ZWIwY2ZiOGI0YWIyMjcyOWIuMWY0ZmVmZDUtODliMi00ZTkyLWJhZGYtODdlYzY0YmQ4NjQ2' \
--header 'Content-Type: application/json' \
--data-raw '{
    "name": "Minerva2",
    "metastore_params": {
        "apikey": "YXRsYXNfNDBkMTMwMDY4NTM4OTM3ZWIwY2ZiOGI0YWIyMjcyOWIuMWY0ZmVmZDUtODliMi00ZTkyLWJhZGYtODdlYzY0YmQ4NjQ2",
        "cluster": "minervaa"
    },
    "loader": "MinervaMetadataLoader",
    "acl_control": {}
}'

## id => result.data.id
```

## Create Query Engine
```shell
curl --location --request POST 'http://127.0.0.1:10001/querybook/ds/admin/query_engine/' \
--header 'Origin: http://google.com' \
--header 'Authorization: Bearer YXRsYXNfNDBkMTMwMDY4NTM4OTM3ZWIwY2ZiOGI0YWIyMjcyOWIuMWY0ZmVmZDUtODliMi00ZTkyLWJhZGYtODdlYzY0YmQ4NjQ2' \
--header 'Content-Type: application/json' \
--data-raw '{
    "name": "Minervac",
    "description": "Minervac",
    "language": "Minerva",
    "executor": "Minerva",
    "executor_params": {
        "apikey": "YXRsYXNfNDBkMTMwMDY4NTM4OTM3ZWIwY2ZiOGI0YWIyMjcyOWIuMWY0ZmVmZDUtODliMi00ZTkyLWJhZGYtODdlYzY0YmQ4NjQ2",
        "cluster": "minervaa"
    },
    "metastore_id": "2",
    "feature_params": {
        "status_checker": "SelectOneChecker"
    }
}'
```

## Schedule Metadata Store Update
```shell
curl --location --request POST 'http://127.0.0.1:10001/querybook/ds/schedule/' \
--header 'Origin: http://google.com' \
--header 'Authorization: Bearer YXRsYXNfNDBkMTMwMDY4NTM4OTM3ZWIwY2ZiOGI0YWIyMjcyOWIuMWY0ZmVmZDUtODliMi00ZTkyLWJhZGYtODdlYzY0YmQ4NjQ2' \
--header 'Content-Type: application/json' \
--data-raw '{
    "cron": "0 0 * * *",
    "name": "update_metastore_4",
    "task": "tasks.update_metastore.update_metastore",
    "task_type": "prod",
    "enabled": true,
    "args": [
        4
    ],
    "kwargs": {}
}'
```
