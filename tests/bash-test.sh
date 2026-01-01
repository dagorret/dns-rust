#!/bin/bash

SERVER="127.0.0.1"
PORT="1053"
DOMAIN="ejemplo.com"

# Clasificación de registros para un testeo exhaustivo
TYPES=(
    # --- Básicos y Direccionamiento ---
    "A" "AAAA" "CNAME" "PTR" 
    
    # --- Correo y Texto ---
    "MX" "TXT" "SPF" 
    
    # --- Autoridad e Infraestructura ---
    "NS" "SOA" "HINFO" "RP" 
    
    # --- Servicios y Localización ---
    "SRV" "LOC" "NAPTR"
    
    # --- Seguridad y DNSSEC (Cruciales si tu server los soporta) ---
    "DNSKEY" "DS" "RRSIG" "NSEC" "NSEC3" "TLSA" "CAA"
    
    # --- Otros / Experimentales ---
    "DNAME" "SSHFP"
)

echo "--- Test Exhaustivo de Tipos de Registro DNS ---"
echo "Servidor: $SERVER:$PORT | Dominio: $DOMAIN"
echo "-----------------------------------------------"

for TYPE in "${TYPES[@]}"; do
    # Realizamos la consulta capturando el encabezado para el status
    OUTPUT=$(dig @$SERVER -p $PORT $DOMAIN $TYPE)
    STATUS=$(echo "$OUTPUT" | grep "status:" | awk '{print $6}' | tr -d ',')
    
    # Capturamos la sección ANSWER
    ANSWER=$(echo "$OUTPUT" | sed -n '/;; ANSWER SECTION:/,/^$/p' | tail -n +2)

    if [[ "$STATUS" == "NOERROR" ]]; then
        echo -e "[\e[32m$TYPE\e[0m] -> Status: NOERROR"
        if [[ ! -z "$ANSWER" ]]; then
            echo "$ANSWER" | sed 's/^/    /'
        fi
    else
        echo -e "[\e[31m$TYPE\e[0m] -> Status: $STATUS"
    fi
done

# Intento de transferencia de zona (AXFR) - Muy importante para testear seguridad
echo -e "\n--- Probando Transferencia de Zona (AXFR) ---"
dig @$SERVER -p $PORT $DOMAIN AXFR | grep -E "Transfer failed|communications error" && \
echo "AXFR denegado/fallido (Normal si está protegido)" || echo "AXFR Permitido (Ojo con la seguridad)"
