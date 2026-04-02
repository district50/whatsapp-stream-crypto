.PHONY: test coverage phpstan clean install

install:
	composer install

update:
	composer update

test:
	vendor/bin/phpunit

coverage:
	vendor/bin/phpunit --coverage-html coverage

phpstan:
	vendor/bin/phpstan analyse src/ --level=8

clean:
	rm -rf vendor/ composer.lock coverage/

all: clean install test phpstan