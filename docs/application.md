# アプリケーション

## アプリのWeb UIを見たい

グローバルIPアドレス、もしくは提供されているFQDNがあればそれにアクセスする。

もしこれらが提供されていない場合、sshでポートフォワードして繋ぐ。

```
ssh -NL 8081:localhost:80 isu1
ssh -NL 8082:localhost:80 isu2
ssh -NL 8083:localhost:80 isu3
```

グローバルIPアドレスでアクセス出来ない、かつ、アクセス先が特定のFQDNを要求する場合、 `/etc/hosts` に追記してブラウザを再起動し、そのFQDNにアクセスする。

```
FQDN=
echo "127.0.0.1 ${FQDN}" | sudo tee /etc/hosts
```

## pprofのWebUIを見る

アプリケーションとは異なるポートでpprofにアクセスする必要がある場合、何らかの事情によりグローバルIPアドレスでアクセス出来ない場合、これもまたポートフォワードで繋ぐ。

```
ssh -NL 6061:localhost:6060 isu1
ssh -NL 6062:localhost:6060 isu2
ssh -NL 6063:localhost:6060 isu3
```

## 標準出力に吐いたログを見たい

おそらくsystemdを使ってデーモンが管理されており、journaldによってログが管理されているはず。
まずはアプリケーションのsystemd unitを特定する。

```
sudo ls -l /etc/systemd/system/
```

上記に含まれる（であろう）systemd unitの名前を指定してjournalctlでログを表示する。

```
UNIT=
journalctl -u ${UNIT}
```

ログをtailする（ログ出力を監視して表示し続ける）場合：

```
journalctl -f -u ${UNIT}
```

## アプリケーションのプロセスの状態を見たい

Web UIにアクセスしたが、APIへのアクセスが502などになっていてうまく表示されないなど、アプリケーションのプロセスに何らかの問題が発生していると想定される場合。

アプリケーションのプロセス自体が生きているかどうかは以下のコマンドで確認する。

```
UNIT=
systemctl status ${UNIT}
```

起動する

```
sudo systemctl start ${UNIT}
```

再起動する

```
sudo systemctl restart ${UNIT}
```
