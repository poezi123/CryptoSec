PREFIX  ?= /usr/local
DESTDIR ?=
CARGO   ?= cargo

BIN     := target/release/cryptosec

.PHONY: all build test install uninstall update-caches clean

all: build

build:
	$(CARGO) build --release --locked

test:
	$(CARGO) test --release --locked

$(BIN): build

install: $(BIN)
	install -Dm755 $(BIN) $(DESTDIR)$(PREFIX)/bin/cryptosec
	install -Dm644 docs/cryptosec.1 $(DESTDIR)$(PREFIX)/share/man/man1/cryptosec.1
	install -Dm644 packaging/desktop/cryptosec.desktop $(DESTDIR)$(PREFIX)/share/applications/cryptosec.desktop
	install -Dm644 packaging/desktop/cryptosec.xml $(DESTDIR)$(PREFIX)/share/mime/packages/cryptosec.xml
	install -Dm644 README.md $(DESTDIR)$(PREFIX)/share/doc/cryptosec/README.md
	install -Dm644 LICENSE $(DESTDIR)$(PREFIX)/share/doc/cryptosec/LICENSE

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/cryptosec
	rm -f $(DESTDIR)$(PREFIX)/share/man/man1/cryptosec.1
	rm -f $(DESTDIR)$(PREFIX)/share/applications/cryptosec.desktop
	rm -f $(DESTDIR)$(PREFIX)/share/mime/packages/cryptosec.xml
	rm -rf $(DESTDIR)$(PREFIX)/share/doc/cryptosec

# Only for a direct "make install"; the packages let their own hooks do this.
update-caches:
	-update-mime-database $(DESTDIR)$(PREFIX)/share/mime
	-update-desktop-database $(DESTDIR)$(PREFIX)/share/applications

clean:
	$(CARGO) clean
