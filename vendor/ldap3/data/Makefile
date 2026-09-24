all:
	@echo "Targets: clean, db"

clean: do-clean

db: do-db

do-clean:
	@./stopdb.sh 2>/dev/null || exit 0
	rm -rf db config

do-db:
	mkdir db db/main db/run config
	slapadd -n0 -q -F config -l config-core.ldif
	slapadd -n0 -q -F config -l core.ldif
	slapadd -n0 -q -F config -l cosine.ldif
	slapadd -n0 -q -F config -l inetorgperson.ldif
	slapadd -n0 -q -F config -l nis.ldif
	slapd -h ldapi://ldapi -F config
	sleep 1
	ldapadd -x -D "cn=config" -w secret -H ldapi://ldapi -f add-db.ldif
	kill `cat db/run/db.pid`
	slapadd -n1 -qw -F config -l example.ldif
