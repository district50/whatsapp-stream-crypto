<?php
	
	namespace District50\WhatsAppStreamCrypto\Exception;
	
	/**
	 * Исключение для ошибок целостности данных (HMAC не совпадает)
	 */
	class IntegrityException extends CryptoException {
		/**
		 * Создает исключение при несовпадении MAC
		 */
		public static function macMismatch(): self {
			return new self( 'MAC verification failed: data integrity compromised' );
		}
		
		/**
		 * Создает исключение при ошибке генерации sidecar
		 */
		public static function sidecarGenerationFailed( string $message ): self {
			return new self( 'Sidecar generation failed: ' . $message );
		}
	}