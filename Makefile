.PHONY: all watch clean

all:
	webpack

watch:
	webpack --progress --colors --watch

clean:
	rm background.js
