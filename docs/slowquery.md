# Slow query

## スロークエリログの有効化

以下のコマンドを実行する。

```
make enable-slowquery-log
```

これによって[enable_slow_query.yml](../playbooks/enable_slow_query.yml)が実行される。
このplaybookはdbグループのホストに対してのみ実行されるため、それ以外のホストでは有効化されないことに注意する。

また、これはMySQLの以下のグローバル変数を設定することでスロークエリを有効化している。

| 変数名 | 値  |
| ------ | --- |
| slow_query_log | ON |
| slow_query_log_file | /tmp/slow_query.log |
| long_query_time | 0.01 |

これらの値はMySQLを再起動することによって揮発するため、再起動後にはスロークエリログは無効化される。
再び有効にしたい場合、コマンドを再実行する。

## スロークエリログの無効化

MySQLを再起動する。

```
sudo systemctl restart mysql
```

もしくはホストを再起動する。

```
sudo reboot
```

もしくは以下のコマンドを実行する。

```
make disable-slowquery-log
```

## スロークエリログの閲覧

スロークエリログはmysqlユーザによって作成されるため、閲覧にはsudoが必要。

```
sudo mysqldumpslow /tmp/slow_query.log | less
```

### mysqldumpslowのオプション

デフォルトでは平均実行時間でソートされている。このソート順は以下のオプションで変更できる。

| オプション | ソート順 |
| ---------- | -------- |
| `-s at`    | 平均実行時間 |
| `-s ar`    | 取得/更新した平均行数 |
| `-s al`    | 平均ロック時間 |
| `-s c`     | 総実行回数 |
| `-s t`     | 総実行時間 |
| `-s l`     | 総ロック時間 |
| `-s r`     | 総取得/更新行数 |

### mysqldumpslowの見方

クエリのパラメータは `N` で埋められる。

```
Count: 37  Time=0.14s (5s)  Lock=0.00s (0s)  Rows=278.0 (10286), isucon[isucon]@localhost
  SELECT * FROM estate WHERE latitude <= N.N AND latitude >= N.N AND longitude <= N.N AND longitude >= N.N ORDER BY popularity DESC, id ASC
```

| 項目 | 意味する物 | 備考 |
| ---- | ---------- | ---- |
| Count | 実行回数 | |
| Time | 平均実行時間 | 括弧内はその合計 |
| Lock | 平均ロック時間 | 括弧内はその合計 |
| Rows | 平均取得/更新行数 | 括弧内はその合計 |
| `isucon[isucon]@localhost` | 実行ユーザ、データベース、実行ホスト |
| `SELECT * ...` | 実行クエリ | |

## pt-query-digestによる調査

pt-query-digestはPerconaが作っているスロークエリ解析を行えるツールである。

https://www.percona.com/doc/percona-toolkit/3.0/pt-query-digest.html

```
sudo pt-query-digest /tmp/slow_query.log | less
```

### 解析結果の読み方

pt-query-digestの解析結果は3つのパートからなる。

1. クエリ横断の概要
2. クエリのランキング
3. 各クエリの詳細

```
# 910ms user time, 10ms system time, 31.44M rss, 86.77M vsz
# Current date: Mon Jul 18 01:14:16 2022
# Hostname: isucon10-qualify-web001
# Files: /tmp/slow_query.log
# Overall: 4.51k total, 73 unique, 70.53 QPS, 6.32x concurrency __________
# Time range: 2022-07-18T01:11:23 to 2022-07-18T01:12:27
# Attribute          total     min     max     avg     95%  stddev  median
# ============     ======= ======= ======= ======= ======= ======= =======
# Exec time           405s    10ms   281ms    90ms   141ms    28ms    82ms
# Lock time          871ms       0    12ms   193us   596us   759us    42us
# Rows sent         70.07k       0   1.11k   15.89   24.84   32.39   19.46
# Rows examine     126.02M       0  30.41k  28.59k  28.66k   4.48k  28.66k
# Query size         7.69M       6 240.93k   1.75k  329.68  18.93k   76.28
```

これがpt-query-digestのクエリ横断の概要を示すセクションである。
以下がクエリのランキングを示す。実際にはProfileのところにもっとクエリが並んでいるかもしれない。

```
# Profile
# Rank Query ID           Response time  Calls R/Call V/M   Item
# ==== ================== ============== ===== ====== ===== =============
#    1 0x387A1968AED87BF9  34.0814  8.4%   250 0.1363  0.01 SELECT estate
#    2 0xA3BBB20FFD7BCE7C  32.9025  8.1%   338 0.0973  0.01 SELECT chair
#    3 0xE37BD5D8F0FF2FDE  29.3096  7.2%   300 0.0977  0.01 SELECT estate
#    4 0x9C572B62B2210476  29.1158  7.2%   339 0.0859  0.00 SELECT estate
#    5 0x30222108492FF4F7  25.3205  6.3%   300 0.0844  0.00 SELECT estate
```

おそらく見るのはProfile以下になると思うので、そこを解説する。

| 項目 | 意味する物 | 備考 |
| ---- | ---------- | ---- |
| Rank | 全クエリの中での順位 | デフォルトはResponse timeの降順 |
| Query ID | クエリのフィンガープリント | 後述するクエリの詳細を見る際に使う |
| Response time | クエリの総実行時間と、全体に占める割合 | |
| Calls | クエリの実行回数 | |
| R/Call | Response time / Call の略。クエリ辺りの平均応答時間 | |
| V/M | 標準偏差 | |
| Item | クエリの一部 | |

リテラルは置き換えられるため、リテラルのみが異なるクエリは同じクエリとして扱われる。ここで解析したいクエリを決め、そのフィンガープリントで検索する。例えばフィンガープリント `0x387A1968AED87BF9` のクエリの詳細は以下。

```
# Query 1: 4.17 QPS, 0.57x concurrency, ID 0x387A1968AED87BF9 at byte 8966165
# This item is included in the report because it matches --limit.
# Scores: V/M = 0.01
# Time range: 2022-07-18T01:11:26 to 2022-07-18T01:12:26
# Attribute    pct   total     min     max     avg     95%  stddev  median
# ============ === ======= ======= ======= ======= ======= ======= =======
# Count          5     250
# Exec time      8     34s    80ms   225ms   136ms   189ms    27ms   128ms
# Lock time      2    22ms    25us     6ms    86us   125us   377us    49us
# Rows sent      6   4.88k      20      20      20      20       0      20
# Rows examine   5   7.16M  28.83k  29.32k  29.31k  28.66k       0  28.66k
# Query size     1  82.01k     329     341  335.91  329.68    4.45  329.68
# String:
# Databases    isuumo
# Hosts        localhost
# Users        isucon
# Query_time distribution
#   1us
#  10us
# 100us
#   1ms
#  10ms  ##
# 100ms  ################################################################
#    1s
#  10s+
# Tables
#    SHOW TABLE STATUS FROM `isuumo` LIKE 'estate'\G
#    SHOW CREATE TABLE `isuumo`.`estate`\G
# EXPLAIN /*!50100 PARTITIONS*/
SELECT * FROM estate WHERE (door_width >= 132 AND door_height >= 166) OR (door_width >= 132 AND door_height >= 74) OR (door_width >= 166 AND door_height >= 132) OR (door_width >= 166 AND door_height >= 74) OR (door_width >= 74 AND door_height >= 132) OR (door_width >= 74 AND door_height >= 166) ORDER BY popularity DESC, id ASC LIMIT 20\G
```

| 項目 | 意味する物 | 備考 |
| ---- | ---------- | ---- |
| Count | クエリの実行回数 | |
| Exec time | クエリの実行時間 |
| Lock time | クエリがロックしていた時間 | |
| Rows sent | クエリで取得された行の数 |
| Rows examime | クエリでスキャンされた行の数 |

`Queri_time distribution` とは、検出されたクエリの中でのクエリ実行時間の分布を示している。上記の結果を見るとほとんどのクエリは100ms以上1s以下に収まっている。

### ソート順の変更

`--order-by` オプションで並び替え順を変えることができる。

https://www.percona.com/doc/percona-toolkit/3.0/pt-query-digest.html#cmdoption-pt-query-digest-order-by

| オプション | ソート順 |
| ---------- | -------- |
| `Query_time:sum` | デフォルト。総実行時間の降順 |
| `Query_time:min` | 最小実行時間の降順 |
| `Query_time:max` | 最大実行時間の降順 |
| `Query_time:cnt` | クエリの実行回数の降順 |

ソート順によっては複数のクエリが `MISC` としてまとめられることがある。これはそのソート順について、上位95パーセンタイルに入らなかったものがまとめられるためである。
例えば実行回数の降順で並び替え、あるクエリが非常に多数実行されていた場合、そのクエリ以外はMISCでまとめられてしまう可能性がある。

これを回避したい場合、いくつかのオプションがある。

#### `--limit` を使う

これは結果に表示する数を変える。

https://www.percona.com/doc/percona-toolkit/3.0/pt-query-digest.html#cmdoption-pt-query-digest-limit

デフォルトは `95%:20`。`:` 区切りの2つのセクションからなる。2つめはオプショナル。これは以下の様な組み合わせで、それぞれ意味が異なる。

- 整数のみの場合
  - 例：`10`
  - 上位10個を表示する。
- パーセントがつく場合
  - 例：`95%`
  - 上位95%に該当するものを表示する。
- `:`区切りで割合と整数が指定された場合
  - 例：`95%:20`
  - 上位95%もしくは20個、どちらか早く到達した方が採用される。

例えばクエリの実行回数の降順で並び替えたとき、ある特定のクエリの実行回数が桁外れに多いと、他のクエリは `MISC` でまとめられてしまう可能性がある。
このとき例えば `--limit 5` などと指定すると、必ず上位5件までは `MISC` にまとめず表示されるようになる。

#### `--outliers` を使う

この条件に引っかかったクエリは、無条件でレポートに含まれる様になる（`--limit` の指定を無視する）。

https://www.percona.com/doc/percona-toolkit/3.0/pt-query-digest.html#cmdoption-pt-query-digest-outliers

デフォルトは `Query_time:1:10`。`:` 区切りの3つのセクションからなる。3つめはオプショナル。これは以下の様な意味をもつ。

```
評価に使う値:そのクエリの95パーセンタイルの値と比較する値:クエリの出現回数
```

つまり `Query_time:1:10` の場合、下記条件に当てはまるクエリは必ず結果に含まれる。

- あるフィンガープリントのクエリについて、実行時間の95パーセンタイルの値が1秒以上
- このクエリが10回以上出現する

## スロークエリログのローテーション

前回のベンチマークの結果と混ざらないように、ベンチマークを実行する前に以下のコマンドを実行してスロークエリログの中身を消去する。

```
make before-bench
```

これにより、以降のログは `/tmp/slow_query.log` に書き込まれ、古いslow_query.logは順に `/tmp/sloq_query.log.1` などのように世代番号の数値のサフィックスが付与されて残る。
デフォルトでは十世代分のログが保存される。

もし何らかの事情によりDBホスト上で直接ローテーションしたい場合、以下のコマンドを実行する。

```
sudo logrotate -f /etc/logrotate.d/slowquery
```

