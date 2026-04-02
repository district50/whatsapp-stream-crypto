<?php
	
	namespace District50\WhatsAppStreamCrypto\Crypto;
	
	/**
	 * Типы медиафайлов и соответствующие информационные строки для HKDF
	 */
	enum MediaType: string {
		case IMAGE = 'WhatsApp Image Keys';
		case VIDEO = 'WhatsApp Video Keys';
		case AUDIO = 'WhatsApp Audio Keys';
		case DOCUMENT = 'WhatsApp Document Keys';
		
		/**
		 * Получить информационную строку для HKDF
		 */
		public function getApplicationInfo(): string {
			return $this->value;
		}
	}