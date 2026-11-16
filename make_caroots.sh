#!/bin/bash

# Location of a checkout of https://github.com/sectigo/CF_CTreq (defaults to a sibling of this repository).
CF_CTREQ_DIR="${CF_CTREQ_DIR:-$(dirname "$(realpath "$0")")/../CF_CTreq}"
ROOTS_HASHES="$(realpath -m "$CF_CTREQ_DIR")/tools/roots-hashes.mjs"
if [ ! -f "$ROOTS_HASHES" ]; then
	# No local checkout, so use a temporary clone.
	CF_CTREQ_TMPDIR="$(mktemp -d)"
	trap 'rm -rf "$CF_CTREQ_TMPDIR"' EXIT
	if ! git clone --quiet --depth 1 https://github.com/sectigo/CF_CTreq.git "$CF_CTREQ_TMPDIR"; then
		echo "Failed to clone CF_CTreq" >&2
		exit 1
	fi
	ROOTS_HASHES="$CF_CTREQ_TMPDIR/tools/roots-hashes.mjs"
fi

function make_caroots_ctreq {
	node "$ROOTS_HASHES" pem/$1-ca-roots.pem > CTreq/$1-accepted-roots.txt
}

function make_caroots_readonly_pem {
	find crt/common/monitoring crt/$1 -iname *.crt 2>/dev/null | sort | xargs cat > pem/$1-ca-roots.pem
}

function make_caroots_prod_tls_pem {
	find crt/common/trusted/tls crt/common/monitoring crt/$1 -iname *.crt 2>/dev/null | sort | xargs cat > pem/$1-ca-roots.pem
}

function make_caroots_prod_bimi_pem {
	find crt/common/trusted/bimi crt/common/monitoring crt/$1 -iname *.crt 2>/dev/null | sort | xargs cat > pem/$1-ca-roots.pem
}

function make_caroots_nonprod1_pem {
	find crt/common/trusted/tls crt/common/non_production crt/$1 -iname *.crt 2>/dev/null | sort | xargs cat > pem/$1-ca-roots.pem
}

function make_caroots_nonprod2_pem {
	find crt/common/non_production crt/$1 -iname *.crt 2>/dev/null | sort | xargs cat > pem/$1-ca-roots.pem
}

function make_caroots_test_pem {
	find crt/$1 -iname *.crt 2>/dev/null | sort | xargs cat > pem/$1-ca-roots.pem
}

function make_caroots_readonly_tsv {
	echo "SHA-256(Certificate)	CA Name" > tsv/$1-ca-roots.tsv
	find crt/common/monitoring crt/$1 -iname *.crt -printf %f -exec openssl x509 -nameopt utf8 -subject -noout -in '{}' ';' 2>/dev/null | sed "s/\.crtsubject=/\t/g" | sort >> tsv/$1-ca-roots.tsv
}

function make_caroots_prod_tls_tsv {
	echo "SHA-256(Certificate)	CA Name" > tsv/$1-ca-roots.tsv
	find crt/common/trusted/tls crt/common/monitoring crt/$1 -iname *.crt -printf %f -exec openssl x509 -nameopt utf8 -subject -noout -in '{}' ';' 2>/dev/null | sed "s/\.crtsubject=/\t/g" | sort >> tsv/$1-ca-roots.tsv
}

function make_caroots_prod_bimi_tsv {
	echo "SHA-256(Certificate)	CA Name" > tsv/$1-ca-roots.tsv
	find crt/common/trusted/bimi crt/common/monitoring crt/$1 -iname *.crt -printf %f -exec openssl x509 -nameopt utf8 -subject -noout -in '{}' ';' 2>/dev/null | sed "s/\.crtsubject=/\t/g" | sort >> tsv/$1-ca-roots.tsv
}

function make_caroots_nonprod1_tsv {
	echo "SHA-256(Certificate)	CA Name" > tsv/$1-ca-roots.tsv
	find crt/common/trusted/tls crt/common/non_production crt/$1 -iname *.crt -printf %f -exec openssl x509 -nameopt utf8 -subject -noout -in '{}' ';' 2>/dev/null | sed "s/\.crtsubject=/\t/g" | sort >> tsv/$1-ca-roots.tsv
}

function make_caroots_nonprod2_tsv {
	echo "SHA-256(Certificate)	CA Name" > tsv/$1-ca-roots.tsv
	find crt/common/non_production crt/$1 -iname *.crt -printf %f -exec openssl x509 -nameopt utf8 -subject -noout -in '{}' ';' 2>/dev/null | sed "s/\.crtsubject=/\t/g" | sort >> tsv/$1-ca-roots.tsv
}

function make_caroots_test_tsv {
	echo "SHA-256(Certificate)	CA Name" > tsv/$1-ca-roots.tsv
	find crt/$1 -iname *.crt -printf %f -exec openssl x509 -nameopt utf8 -subject -noout -in '{}' ';' 2>/dev/null | sed "s/\.crtsubject=/\t/g" | sort >> tsv/$1-ca-roots.tsv
}

make_caroots_readonly_pem mammoth
make_caroots_readonly_pem sabre
make_caroots_prod_tls_pem elephant
make_caroots_prod_tls_pem tiger
make_caroots_prod_tls_pem monument
make_caroots_prod_tls_pem statue
make_caroots_prod_bimi_pem billboard
make_caroots_nonprod1_pem dumbo
make_caroots_nonprod2_pem standee
make_caroots_test_pem tigger

make_caroots_readonly_tsv mammoth
make_caroots_readonly_tsv sabre
make_caroots_prod_tls_tsv elephant
make_caroots_prod_tls_tsv tiger
make_caroots_prod_tls_tsv monument
make_caroots_prod_tls_tsv statue
make_caroots_prod_bimi_tsv billboard
make_caroots_nonprod1_tsv dumbo
make_caroots_nonprod2_tsv standee
make_caroots_test_tsv tigger

mkdir -p CTreq
make_caroots_ctreq mammoth
make_caroots_ctreq sabre
make_caroots_ctreq elephant
make_caroots_ctreq tiger
make_caroots_ctreq monument
make_caroots_ctreq statue
make_caroots_ctreq billboard
make_caroots_ctreq dumbo
make_caroots_ctreq standee
make_caroots_ctreq tigger
