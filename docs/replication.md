# Replication Setup

MySQL 8.0の非同期レプリケーションのセットアップ手順を示す。

## Terminology

- Sourceサーバ
  - 非同期レプリケーションにおける、SourceとなるMySQLホスト
- Replicaサーバ
  - 非同期レプリケーションにおける、ReplicaとなるMySQLホスト
- Source IP
  - SourceサーバのプライベートIPアドレス
- Replica IP
  - ReplicaサーバのプライベートIPアドレス

## 事前に調べること

コンソールないし `ip a` コマンドで各ホストのプライベートアドレスを確認する。Public IP経由でレプリケーションすると無駄な経路を通ってしまうため。

```
SOURCE_IP=
REPLICA_IP=
```

## 1. 設定を変更する

`/etc/mysql/mysql.conf.d/mysqld.cnf` の該当箇所を以下の様に編集する。

```
[mysqld]
bind-address = 0.0.0.0
server-id = 1
# Sourceサーバの場合
log_bin = /var/lib/mysql/mysql-bin
# Replicaサーバの場合
read_only
```

適用したら再起動する。

```
sudo systemctl restart mysql
```

一意なserver-idが必要になるため、以下の様に決める。

- isu1: `1`
- isu2: `2`
- isu3: `3`

SourceサーバのMySQLに接続して `show master status` が表示できればOK

```
mysql> show master status;
+------------------+----------+--------------+------------------+-------------------+
| File             | Position | Binlog_Do_DB | Binlog_Ignore_DB | Executed_Gtid_Set |
+------------------+----------+--------------+------------------+-------------------+
| mysql-bin.000001 |      154 |              |                  |                   |
+------------------+----------+--------------+------------------+-------------------+
1 row in set (0.00 sec)
```

## 2. Sourceサーバにユーザを作成する

```
CREATE USER 'repl'@'%' IDENTIFIED BY 'replication';
GRANT REPLICATION SLAVE ON *.* TO 'repl'@'%';
FLUSH PRIVILEGES;
```

replユーザで接続出来るか確認する。

```
mysql -urepl -preplication
```

Replicaサーバ側からもチェックする

```
mysql -urepl -preplication -h${REPLICA_IP}
```

## 3. SourceのデータをdumpしてReplicaに投入する

SourceとReplicaはデータが揃っている必要があるので、dumpしてリストアする。

Sourceサーバ上で実施
```
mysqldump -uisucon -pisucon --all-databases --master-data --single-transaction --flush-logs --events > all.sql
```

SourceとReplica間で直接送れると嬉しいが面倒なので手元に落としてきてから転送する。

手元のmacOSで実施
```
# isu1,isu2,isu3のいずれかを指定
SOURCE=
# isu1,isu2,isu3のいずれかを指定
REPLICA
scp ${SOURCE}:all.sql ./
scp ./all.sql ${REPLICA}: 
```

Replicaサーバ上で実施

```
mysql -uisucon -pisucon < all.sql
```

## 4. Start slaveする

Source上でのbinlogのポジションを確認する。

```
mysql -uisucon -pisucon -e 'show master status'
```

このFileとPositionをメモしておく。

Replica上でCHANGE MASTERとSTART SLAVEを実行する。

```
SOURCE_IP=
LOG_FILE=
LOG_POS=
mysql -uisucon -pisucon -e "CHANGE MASTER TO MASTER_HOST='${SOURCE_IP}', MASTER_USER='repl', MASTER_PASSWORD='replication', MASTER_LOG_FILE='${LOG_FILE}', MASTER_LOG_POS=${LOG_POS}"
mysql -uisucon -pisucon -e "START SLAVE"
```

SHOW SLAVE STATUSして以下を確認する。

- `Slave_IO_Runnning` と `Slave_SQL_Running` が yes であること
- `Last_Error` が空であること

```
mysql -uisucon -pisucon -e "SHOW SLAVE STATUS \G"
```

## 接続出来ないとき

1. パスワードやユーザ名をtypoしてないか確認する。
2. 接続先ホストが正しいか確認する。
3. セキュリティポリシーでポートが塞がれていないか確認する。
4. `sudo ufw status`でポートが塞がれていないか確認する。
5. `sudo iptables -NL`でポートが塞がれていないか確認する。
