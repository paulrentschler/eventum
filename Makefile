name            := eventum
datadir         := /usr/share/$(name)
sysconfdir      := $(datadir)/config
sbindir         := /usr/sbin
bindir          := /usr/bin
logdir          := /var/log/$(name)
smartyplugindir := $(datadir)/lib/Smarty/plugins

all:
	@echo 'Run "make install" to install eventum.'

install: install-eventum install-cli install-irc install-scm install-libs

dist:
	./bin/release.sh

phpcs:
	phpcs --standard=phpcs.xml --report=emacs --report-width=120 --report-file=`pwd`/phpcs.txt .

box.phar:
	curl -LSs https://box-project.github.io/box2/installer.php | php

composer.phar:
	curl -sS https://getcomposer.org/installer | php

composer.lock:
	composer install

# https://security.sensiolabs.org/api
composer-security-checker: composer.lock
	curl -H "Accept: text/plain" https://security.sensiolabs.org/check_lock -F lock=@composer.lock

# install eventum core
install-eventum:
	install -d $(DESTDIR)$(sysconfdir)
	touch $(DESTDIR)$(sysconfdir)/{config.php,private_key.php,setup.php}

	install -d $(DESTDIR)$(datadir)/lib
	cp -a lib/eventum $(DESTDIR)$(datadir)/lib
	cp -a htdocs $(DESTDIR)$(datadir)
	cp -a templates $(DESTDIR)$(datadir)
	cp -a upgrade $(DESTDIR)$(datadir)
	cp -a bin $(DESTDIR)$(datadir)
	cp -a *.php $(DESTDIR)$(datadir)

	install -d $(DESTDIR)$(logdir)
	touch $(DESTDIR)$(logdir)/{cli.log,errors.log,irc_bot.log,login_attempts.log}

# install eventum cli
install-cli:
	install -d $(DESTDIR)$(bindir)
	install -p cli/$(name).phar $(DESTDIR)$(bindir)/$(name)

# install eventum irc bot
install-irc:
	install -d $(DESTDIR)$(sbindir)
	cp -a irc/eventum-irc-bot.php $(DESTDIR)$(sbindir)/eventum-irc-bot

# install eventum scm (cvs, eventum) hooks
install-scm:
	install -d $(DESTDIR)$(sbindir)
	install -p scm/eventum-cvs-hook.php $(DESTDIR)$(sbindir)/eventum-cvs-hook
	install -p scm/eventum-svn-hook.php $(DESTDIR)$(sbindir)/eventum-svn-hook

# install extra libraries for eventum
install-libs: install-jpgraph

install-jpgraph:
	install -d $(DESTDIR)$(datadir)/lib
	cp -a lib/jpgraph $(DESTDIR)$(datadir)/lib

install-localization:
	$(MAKE) -C localization install
