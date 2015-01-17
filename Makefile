MODULES = odr
COMMANDS = odr-*

all:
	@echo "Nothing to see here. Currently no proper build-system. (See Debian packaging instead.)" && exit 1

test:
	# Run normal unit tests.
	nosetests

clean:
	rm -f $$(find $(MODULES) -name '*.pyc') pytags

lint:
	@# W0105 string statement has no effect - documentation of signals
	pylint \
		'--msg-template={path}:{line}: [{msg_id}({symbol}), {obj}] {msg}' \
		--ignored-classes=_socketobject \
		-r n \
		-d I0011 \
		-d C \
		-d R \
		-d E1101 \
		-d W0105 \
		-E \
		$(MODULES) \
		$(COMMANDS)

ctags:
	ctags -R --python-kinds=-i -o pytags $(MODULES) $(COMMANDS)
