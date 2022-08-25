# Ansible playbooks for isucon

## テンプレートから生成後にやること

### ansible・ghのインストール

```
make deps
```

### ghでログイン

↓のコマンドが通ればOK

```
gh repo view | head
```

通らなければログインする

```
gh auth login
```

## 当日やること

### 対象ホストの記述

`ssh_config`を書く

issueにssh configを書いて貼るので各自でssh configに追記する

### デプロイ対象の設定

各自自分の決められたホストを設定する

- taxio: isu1
- shanpu: isu2
- pudding: isu3

```
echo isu1 > TARGET
```

## デプロイ方法

### 今の状態をデプロイする

未コミットの内容もデプロイされる

```
make deploy
```

### 特定のブランチをデプロイ

stashしてpullしてcheckoutする。Untrackedなファイルが含まれてしまうので注意。

```
BRANCH=
make deploy-${BRANCH}
```

## その他

### ベンチマーク結果の自動レポート

ベンチマークをリクエストする前に、以下のコマンドを実行する。

```
make bench
```

「Enterを押してください」というプロンプトで処理が止まるので、ポータルからベンチマークをリクエストしてEnterを押す。
pprofのプロファイルを90秒間取得するので、それが完了するまで待つ（長ければ調整する）。

再度「Enterを押してください」というプロンプトが出るので、ベンチが終了していたらEnterを押す。
ローカルの `bench_results` ディレクトリ以下にレポートが生成され、同じ内容がリポジトリのissueにも投稿される。

### profile結果のダウンロード

自分がメインで操作しているインスタンス以外で取得されたprofileを取得し、ローカルでpprofを見れるようにする。

```
make download-bench-results
```

これで全台からデータを自動でダウンロードしてくる。

### アプリのコード入手ワンライナー

`/home/isucon/webapp` を取得したい場合

```
ssh isu1 "tar czf - -C /home/isucon webapp" | tar zxf -
```

これでカレントディレクトリに `webapp` ディレクトリができ、全ファイルがコピーされる。

### ミドルウェア関連ファイルのバックアップ

SSHしてバックアップするディレクトリ、ファイルを確認し `inventories/host_vars/ホスト名.yml` に書く。

```
make backup
```

