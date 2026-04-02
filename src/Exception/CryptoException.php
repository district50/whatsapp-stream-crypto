<?php
	
	namespace District50\WhatsAppStreamCrypto\Exception;
	
	/**
	 * Исключение для ошибок криптографических операций
	 */
	class CryptoException extends \RuntimeException {
		/**
		 * Создает исключение для ошибок HKDF
		 */
		public static function hkdfFailed( string $algorithm ): self {
			return new self( sprintf( 'HKDF expansion failed for algorithm: %s', $algorithm ) );
		}
		
		/**
		 * Создает исключение для ошибок шифрования
		 */
		public static function encryptionFailed( string $message = '' ): self {
			return new self( 'Encryption failed: ' . $message );
		}
		
		/**
		 * Создает исключение для ошибок дешифрования
		 */
		public static function decryptionFailed( string $message = '' ): self {
			return new self( 'Decryption failed: ' . $message );
		}
	}