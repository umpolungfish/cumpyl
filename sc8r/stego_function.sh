# Steganographic encoding (layered)
stego_encode() {
    if [ -z "$1" ]; then
        echo "Usage: stego_encode &lt;payload&gt;"
        return 1
    fi
    
    local payload="$1"
    echo "🧨 Layer 1 - Hex encoding:"
    python payload_transmute.py -p "$payload" -m hex -v | tail -1
    
    echo "🧨 Layer 2 - Base64 encoding:"
    python payload_transmute.py -p "$payload" -m base64 -v | tail -1
    
    echo "🧨 Layer 3 - URL encoding:"
    python payload_transmute.py -p "$payload" -m url_encode -v | tail -1
}