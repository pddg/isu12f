SHELL := /bin/bash

ANSIBLE_PLAYBOOK := ansible-playbook
target := master
args= 
DEPLOY_TARGET := -l $(shell cat TARGET)
ANSIBLE := ansible
PLAYBOOK_COMMAND=$(ANSIBLE_PLAYBOOK) $(DEPLOY_TARGET) $(args) 
INVENTORY_COMMAND=ansible-inventory

# DeployのGit操作用
CURRENT_BRANCH:=$(shell git symbolic-ref --short HEAD)

deps:
	brew install ansible gh

ping:
	$(ANSIBLE) -m ping $(DEPLOY_TARGET) all

ping-all:
	$(ANSIBLE) -m ping all

init:
	$(PLAYBOOK_COMMAND) playbooks/init.yml

log_backup:
	$(PLAYBOOK_COMMAND) playbooks/backup_logs.yml

backup:
	$(PLAYBOOK_COMMAND) playbooks/backup.yml

.PHONY: deploy
deploy:
	-$(PLAYBOOK_COMMAND) playbooks/deploy.yml

.PHONY: deploy-%
deploy-%:
	git stash
	git fetch && git checkout $* && git pull
	-$(PLAYBOOK_COMMAND) playbooks/deploy.yml
	git checkout $(CURRENT_BRANCH) && git stash pop

.PHONY: bench
bench:
	$(PLAYBOOK_COMMAND) playbooks/bench.yml

.PHONY: download-bench-results
download-bench-results:
	ansible-playbook playbooks/download_bench_results.yml

.PHONY: enable-slowquery-log
enable-slowquery-log:
	$(PLAYBOOK_COMMAND) playbooks/enable_slow_query.yml

.PHONY: disable-slowquery-log
disable-slowquery-log:
	$(PLAYBOOK_COMMAND) playbooks/disable_slow_query.yml

.PHONY: deps log_backup backup ping ping-all
