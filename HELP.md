## Minerva Setup

```shell
curl --location --request POST 'http://127.0.0.1:10001/querybook/ds/admin/minerva_set_up' \
--header 'apikey: cXVlcnlib29rX2FmNzRjZjdhODIyOTU2NzU2NGNjZDc4YTRlNjcyY2Q4LjE0MjU0YTVjLTM5MjAtNDc4My1iYzFmLWFkNTNhMmQ5YWI5NA==' \
--header 'Content-Type: application/json' \
--data-raw '{
    "cluster_name": "minervaa",
    "environment_name": "minervaa",
    "metastore_name": "minervaa",
    "engine_name": "minervaa"
}'
```

## SQLite Demo Setup

```shell
curl --location --request POST 'http://127.0.0.1:10001/querybook/ds/admin/demo_set_up' \
--header 'apikey: cXVlcnlib29rX2FmNzRjZjdhODIyOTU2NzU2NGNjZDc4YTRlNjcyY2Q4LjE0MjU0YTVjLTM5MjAtNDc4My1iYzFmLWFkNTNhMmQ5YWI5NA=='
```
