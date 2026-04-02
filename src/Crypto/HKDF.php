<?php
	
	namespace District50\WhatsAppStreamCrypto\Crypto;
	
	/**
	 * Реализация HKDF (HMAC-based Key Derivation Function)
	 *
	 * Класс для безопасного расширения ключей с использованием HMAC-SHA256
	 * согласно RFC 5869
	 */
	class HKDF {
		/**
		 * Расширяет ключ с помощью HKDF
		 *
		 * @param string $key Исходный ключ (32 байта)
		 * @param int $length Необходимая длина выходных данных в байтах
		 * @param string $info Контекстная информация (application info)
		 * @param string $salt Соль (опционально)
		 *
		 * @return string Расширенный ключ
		 * @throws \InvalidArgumentException Если длина ключа не 32 байта
		 */
		public static function expand(
			string $key,
			int $length,
			string $info = '',
			string $salt = ''
		): string {
			// Проверяем длину ключа
			if( strlen( $key ) !== 32 ) {
				throw new \InvalidArgumentException(
					sprintf( 'Key must be 32 bytes, got %d bytes', strlen( $key ) )
				);
			}
			
			// HKDF-Extract
			if( $salt === '' ) {
				$salt = str_repeat( "\0", 32 );
			}
			$prk = hash_hmac( 'sha256', $key, $salt, true );
			
			// HKDF-Expand
			$output = '';
			$counter = 1;
			$previous = '';
			
			while( strlen( $output ) < $length ) {
				$previous = hash_hmac( 'sha256', $previous . $info . chr( $counter ), $prk, true );
				$output .= $previous;
				$counter++;
			}
			
			return substr( $output, 0, $length );
		}
	}