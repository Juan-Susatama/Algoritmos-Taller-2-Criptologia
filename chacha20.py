import struct

def rotl(a, b):
    """Rotación a la izquierda (circular) de 32 bits."""
    return ((a << b) | (a >> (32 - b))) & 0xFFFFFFFF

def quarter_round(a, b, c, d):
    """
    Función de Cuarto de Ronda (Quarter-Round).
    Modifica las 4 palabras proporcionadas.
    """
    a = (a + b) & 0xFFFFFFFF; d ^= a; d = rotl(d, 16)
    c = (c + d) & 0xFFFFFFFF; b ^= c; b = rotl(b, 12)
    a = (a + b) & 0xFFFFFFFF; d ^= a; d = rotl(d, 8)
    c = (c + d) & 0xFFFFFFFF; b ^= c; b = rotl(b, 7)
    return a, b, c, d

def test_quarter_round():
    """
    Prueba el funcionamiento de la función QR según la Sección 2.1.1 del RFC 7539.
    """
    print("--- PRUEBA DEL QUARTER ROUND (SECCIÓN 2.1.1 RFC 7539) ---")
    a = 0x11111111
    b = 0x01020304
    c = 0x9b8d6f5e
    d = 0x01234567
    
    print(f"Entrada: a={a:08x}, b={b:08x}, c={c:08x}, d={d:08x}")
    a_out, b_out, c_out, d_out = quarter_round(a, b, c, d)
    print(f"Salida:  a={a_out:08x}, b={b_out:08x}, c={c_out:08x}, d={d_out:08x}\n")

def print_state(state, round_num=None):
    if round_num is not None:
        if isinstance(round_num, str):
            print(f"State {round_num}:")
        else:
            print(f"State after {round_num} rounds:")
    else:
        print("Initial state:")
    
    for i in range(0, 16, 4):
        print(f"{state[i]:08x}  {state[i+1]:08x}  {state[i+2]:08x}  {state[i+3]:08x}")
    print()

def chacha_block(key, nonce, block_count, print_rounds=False):
    """
    Genera un bloque de 64 bytes de la palabra cifrante (keystream)
    aplicando las 20 rondas de ChaCha.
    """
    state = [0] * 16
    # Constantes mágicas
    state[0] = 0x61707865
    state[1] = 0x3320646e
    state[2] = 0x79622d32
    state[3] = 0x6b206574
    
    # Clave de 256 bits (8 palabras de 32 bits)
    state[4:12] = struct.unpack('<8I', key)
    
    # Contador de bloque (1 palabra de 32 bits)
    state[12] = block_count
    
    # Nonce de 96 bits (3 palabras de 32 bits)
    state[13:16] = struct.unpack('<3I', nonce)
    
    if print_rounds:
        print_state(state)
        
    working_state = list(state)
    
    # Las 20 rondas
    for i in range(10):
        # Rondas de columna
        working_state[0], working_state[4], working_state[8], working_state[12] = quarter_round(working_state[0], working_state[4], working_state[8], working_state[12])
        working_state[1], working_state[5], working_state[9], working_state[13] = quarter_round(working_state[1], working_state[5], working_state[9], working_state[13])
        working_state[2], working_state[6], working_state[10], working_state[14] = quarter_round(working_state[2], working_state[6], working_state[10], working_state[14])
        working_state[3], working_state[7], working_state[11], working_state[15] = quarter_round(working_state[3], working_state[7], working_state[11], working_state[15])
        
        if print_rounds:
            print_state(working_state, i * 2 + 1)
            
        # Rondas diagonales
        working_state[0], working_state[5], working_state[10], working_state[15] = quarter_round(working_state[0], working_state[5], working_state[10], working_state[15])
        working_state[1], working_state[6], working_state[11], working_state[12] = quarter_round(working_state[1], working_state[6], working_state[11], working_state[12])
        working_state[2], working_state[7], working_state[8], working_state[13] = quarter_round(working_state[2], working_state[7], working_state[8], working_state[13])
        working_state[3], working_state[4], working_state[9], working_state[14] = quarter_round(working_state[3], working_state[4], working_state[9], working_state[14])

        if print_rounds:
            print_state(working_state, i * 2 + 2)

    for i in range(16):
        working_state[i] = (working_state[i] + state[i]) & 0xFFFFFFFF
        
    if print_rounds:
        print_state(working_state, "final (after adding initial state)")
        
    return struct.pack('<16I', *working_state)

def chacha20_process(key, nonce, data, initial_count=1, is_encrypt=True):
    block_count = initial_count
    keystream_total = b''
    resultado_bytes = b''
    
    print(f"--- INICIANDO {'CIFRADO' if is_encrypt else 'DESCIFRADO'} ---")
    
    for i in range(0, len(data), 64):
        print_rondas = (i == 0) 
        if print_rondas:
            print(f"Mostrando rondas para el bloque inicial (contador={block_count}):\n")
            
        block_keystream = chacha_block(key, nonce, block_count, print_rounds=print_rondas)
        
        chunk = data[i:i+64]
        keystream_total += block_keystream[:len(chunk)]
        
        chunk_resultado = bytes(a ^ b for a, b in zip(chunk, block_keystream))
        resultado_bytes += chunk_resultado
        
        block_count += 1
        
    print(f"\n--- RESULTADOS DEL {'CIFRADO' if is_encrypt else 'DESCIFRADO'} ---")
    print(f"Datos de entrada (hex): {data.hex()}")
    print(f"Palabra cifrante (keystream) total: {keystream_total.hex()}")
    print(f"Datos resultantes (hex): {resultado_bytes.hex()}")
    print(f"Estado final del nonce utilizado: {nonce.hex()}")
    print(f"Contador de bloque al terminar: {block_count - 1}\n")
    
    return resultado_bytes

def main():
    # 1. Pruebas de la función QR
    test_quarter_round()
    
    # 2. Configuración para cifrado con parámetros solicitados
    mensaje_original = "Este mensaje de prueba será cifrado con ChaCha20, un algoritmo de flujo rápido y seguro que usa una clave de 256 bits ahora."
    datos_entrada = mensaje_original.encode('utf-8')
    
    # Rellenar con ceros (padding) para ajustar a bloques de 512 bits (64 bytes)
    pad_len = (64 - (len(datos_entrada) % 64)) % 64
    datos_entrada += b'\x00' * pad_len
    
    print(f"Mensaje original codificado en UTF-8 y ajustado con {pad_len} bytes de ceros a {len(datos_entrada)} bytes.")
    
    # Clave de 256 bits (32 bytes)
    clave_hex = "00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f"
    clave = bytes.fromhex(clave_hex.replace(':', ''))
    
    # Nonce de 96 bits (12 bytes)
    nonce_hex = "00:00:00:09:00:00:00:4a:00:00:00:00"
    nonce = bytes.fromhex(nonce_hex.replace(':', ''))
    
    # Contador
    cuenta_inicial = 1
    
    # 3. Cifrado
    texto_cifrado = chacha20_process(clave, nonce, datos_entrada, initial_count=cuenta_inicial, is_encrypt=True)
    
    # 4. Descifrado
    texto_descifrado = chacha20_process(clave, nonce, texto_cifrado, initial_count=cuenta_inicial, is_encrypt=False)
    
    texto_descifrado_sin_pad = texto_descifrado.rstrip(b'\x00')
    mensaje_descifrado = texto_descifrado_sin_pad.decode('utf-8')
    
    print("--- COMPROBACIÓN FINAL ---")
    print(f"Mensaje descifrado correctamente: '{mensaje_descifrado}'")
    if mensaje_original == mensaje_descifrado:
        print("¡El descifrado coincide exitosamente con el original!")
    else:
        print("¡Error! El mensaje descifrado no coincide.")

if __name__ == '__main__':
    main()
