#!/bin/sh

function gen_cert_name ()
{
    echo cert_$(date +%Y-%b-%d_%H-%M-%S)
}

function gen_cert ()
{
    local cert_name

    if [ ! -z "$1" ]; then
        cert_name="cert_$1"
    else
        cert_name="$(gen_cert_name)"
    fi

    echo "Generating new certificate. Output dir: $cert_name"

    if [ -d "$cert_name" ]; then
        echo "Directory $cert_name exists, abort."
        exit 1
    else
        mkdir "$cert_name"
        openssl req -x509 -newkey rsa:2048 \
            -keyout "$cert_name"/key.pem \
            -out "$cert_name"/cert.pem \
            -days 365 -nodes
        cat "$cert_name"/cert.pem >> "$cert_name"/key.pem
    fi
}

gen_cert $@
