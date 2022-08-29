SHELL := /bin/bash
VERSION := 0.0.6
GIT_TAG=$(shell git describe --tags --abbrev=0)
GIT_VERSION=$(shell git describe --tags --dirty)
DOCKER_TAG=$(GIT_VERSION)
BUILD_DATE=$(shell date +"%m/%d/%Y %H:%M:%S %z")
.PHONY: bundled_off prod_web prod_worker prod_scheduler docs remove_running_dev_image clean

bundled_pg: dev_image
	docker-compose -f docker-compose.pg.yml up

bundled_pg_off:
	docker-compose -f docker-compose.pg.yml down

bundled: dev_image
	docker-compose up

bundled_off:
	docker-compose down

web: dev_image remove_running_dev_image
	docker-compose -f containers/docker-compose.dev.yml run web

worker: dev_image
	docker-compose -f containers/docker-compose.dev.yml run worker

scheduler: dev_image
	docker-compose -f containers/docker-compose.dev.yml run scheduler

terminal: dev_image
	docker-compose -f containers/docker-compose.dev.yml run terminal

prod_web:
	docker-compose -f containers/docker-compose.prod.yml run web

prod_worker:
	docker-compose -f containers/docker-compose.prod.yml run worker

prod_scheduler:
	docker-compose -f containers/docker-compose.prod.yml run scheduler

#prod_image:
#	docker build --pull -t querybook . --build-arg PRODUCTION=true --build-arg EXTRA_PIP_INSTALLS=dev.txt,extra.txt,prod.txt

dev_image:
	docker build --pull -t querybook-dev . --build-arg PRODUCTION=false --build-arg EXTRA_PIP_INSTALLS=dev.txt,extra.txt

test_image:
	docker build --pull -t querybook-test . --build-arg PRODUCTION=false --build-arg EXTRA_PIP_INSTALLS=test.txt

docs_image:
	docker build --pull -t querybook-docs . -f docs_website/Dockerfile

docs:
	docker-compose -f docs_website/docker-compose.yml --project-directory=. up --build

install: install_pip_runtime_dependencies install_yarn_packages

install_pip_runtime_dependencies:
	pip install -r ./requirements.txt

install_yarn_packages: node_modules
node_modules: package.json
	yarn install --ignore-scripts --frozen-lockfile --pure-lockfile --ignore-engines
	touch node_modules

remove_running_dev_image:
	$(eval RUNNING_CONTAINERS=$(shell sh -c 'docker ps -q --filter name=querybook_devserver'))
	docker kill $(RUNNING_CONTAINERS) || true

test: test_image
	docker-compose --file containers/docker-compose.test.yml up --abort-on-container-exit

clean: clean_pyc clean_docker
clean_pyc:
	find . -name "*.pyc" -delete
	find . -type d -name __pycache__ -delete
clean_docker:
	docker system prune --volumes

prepare: # Updates app version
	@sed -i.bak "s/\"version\":.*/\"version\": \"${VERSION}\",/" package.json
	@cat package.json | grep "version"

prod_image:
	docker build --pull -t rubiklabs/querybook:${DOCKER_TAG} . --build-arg PRODUCTION=true --build-arg EXTRA_PIP_INSTALLS=extra.txt

prod_push: prod_image
	docker push rubiklabs/querybook:${DOCKER_TAG}
