COMPOSER := $(shell which composer.phar 2>/dev/null || which composer 2>/dev/null || echo false)
BOX := $(shell which box.phar 2>/dev/null || which box 2>/dev/null || echo false)

all:
	@echo 'Run "make eventum.phar" to build standalone eventum cli phar.'

eventum.phar:
	 # setup clean tree as can't seem to find a way to include parent dirs
	 # also main eventum composer.json includes too much deps
	 rm -rf build
	 install -d build/{cli,lib/eventum,vendor}
	 cp -p *.php eventumrc build/cli
	 cp -p *.json *.json.dist build
	 cp -a ../lib/eventum/*  build/lib/eventum
	 cp -a ../vendor/autoload-dist.php  build/vendor
	 cd build && $(COMPOSER) install --prefer-dist
	 cd build && $(BOX) build -v
	 mv -f build/cli/eventum.phar .
	 rm -rf build

clean:
	rm -vf *.phar

.PHONY: eventum.phar