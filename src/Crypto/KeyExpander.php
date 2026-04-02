<?php
	namespace District50\WhatsAppStreamCrypto\Crypto;
	/**
	 * Расширитель ключа для WhatsApp медиа
	 *
	 * Отвечает за расширение mediaKey до 112 байт и разделение на:
	 * - iv (16 байт)
	 * - cipherKey (32 байта)
	 * - macKey (32 байта)
	 * - refKey (32 байта)
	 */
	class KeyExpander {
		private string $iv;
		private string $cipherKey;
		private string $macKey;
		private string $refKey;
		
		/**
		 * Конструктор
		 *
		 * @param string $mediaKey Исходный ключ (32 байта)
		 * @param MediaType $mediaType Тип медиа для информационной строки
		 *
		 * @throws \InvalidArgumentException Если mediaKey не 32 байта
		 */
		public function __construct( string $mediaKey, MediaType $mediaType ) {
			if( strlen( $mediaKey ) !== 32 ) {
				throw new \InvalidArgumentException(
					sprintf( 'Media key must be 32 bytes, got %d bytes', strlen( $mediaKey ) )
				);
			}
			
			// Расширяем ключ до 112 байт
			$expanded = HKDF::expand(
				$mediaKey,
				112,
				$mediaType->getApplicationInfo()
			);
			
			// Разделяем на компоненты
			$this->iv = substr( $expanded, 0, 16 );
			$this->cipherKey = substr( $expanded, 16, 32 );
			$this->macKey = substr( $expanded, 48, 32 );
			$this->refKey = substr( $expanded, 80, 32 );
		}
		
		/**
		 * Получить IV (инициализационный вектор)
		 */
		public function getIv(): string {
			return $this->iv;
		}
		
		/**
		 * Получить ключ для шифрования (AES-CBC)
		 */
		public function getCipherKey(): string {
			return $this->cipherKey;
		}
		
		/**
		 * Получить ключ для HMAC
		 */
		public function getMacKey(): string {
			return $this->macKey;
		}
		
		/**
		 * Получить reference key (не используется)
		 */
		public function getRefKey(): string {
			return $this->refKey;
		}
	}