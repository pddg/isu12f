# トラブルシューティング

## ディスク容量が溢れた

### aptキャッシュの削除

```
sudo apt clean
sudo apt autoremove --purge
```

### バイナリログの削除

MySQLのbinlogを有効化している場合、パージする。
binlogはデフォルトで10日間保存されるため、ISUCON期間中にベンチを叩きまくっているとディスクが溢れる可能性がある。

Sourceでmaster logsを見る。

```
mysql -u isucon -pisucon -e "show master logs"
```

こんな感じの結果が出てくる。

```
+------------------+-----------+
| Log_name         | File_size |
+------------------+-----------+
| mysql-bin.000001 |       796 |
| mysql-bin.000002 |  24669024 |
| mysql-bin.000003 |  24669001 |
+------------------+-----------+
3 rows in set (0.00 sec)
```

このとき、最新のログは `mysql-bin.000003` である。ここまでのログを消すことができる。

```
mysql -u isucon -pisucon -e "PURGE MASTER LOGS TO 'mysql-bin.000003'"
```

消えたことを確認する。

```
mysql -u isucon -pisucon -e "show master logs"
```

消えていればOK

```
+------------------+-----------+
| Log_name         | File_size |
+------------------+-----------+
| mysql-bin.000003 |  24669001 |
+------------------+-----------+
1 row in set (0.00 sec)
```

## 他のホストのMySQLに接続出来ない

### ユーザの確認

MySQLのユーザはユーザと接続元ホストの組み合わせで認証される。

```
mysql -uisucon -pisucon -e 'SELECT user,host FROM mysql.user'
```

以下のようにisuconユーザにはlocalhostからの接続しか許可されていないかもしれない。

```
+------------------+-----------+
| user             | host      |
+------------------+-----------+
| debian-sys-maint | localhost |
| isucon           | localhost |
| mysql.session    | localhost |
| mysql.sys        | localhost |
| root             | localhost |
+------------------+-----------+
5 rows in set (0.00 sec)
```

isuconユーザに対して全ホストを許可する。

```
CREATE USER 'isucon'@'%' IDENTIFIED BY 'isucon';
GRANT ALL ON *.* TO 'isucon'@'%';
FLUSH PRIVILEGES;
```

### MySQLのリッスンアドレスの確認

デフォルトでは `bind-address = 127.0.0.1` になっておりローカルホストからしかリッスンしていない。

```
isucon@isucon10-qualify-web002:~$ netstat -ln | grep 3306
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN
isucon@isucon10-qualify-web002:~$
```

以下の様に `/etc/mysql/mysql.conf.d/mysqld.cnf` のbind-addressを変更して再起動する。

```
bind-address = 0.0.0.0
```

netstatで確認する。

```
netstat -ln | grep 3306
```

以下の様になっていればOK。

```
tcp        0      0 0.0.0.0:3306           0.0.0.0:*               LISTEN
```

### セキュリティポリシーの確認

AWSなどクラウドプロバイダのレベルでインターナルな通信であってもフィルタしてしまっている可能性がある。
コンソールから確認すること。

## ポートフォワードがうまく動かない

以下の様なエラーが出る場合、ssh先に接続出来たとしてもポートフォワードは無効になっている（セキュリティのため）。

```
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
```

接続先のIPアドレスないしFQDNを特定し、以下のコマンドを実行した後にポートフォワードを貼り直し改善しないか試す。

```
TARGET_HOST=
ssh-keygen -R "${TARGET_HOST}"
```
