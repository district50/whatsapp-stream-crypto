<?php
	
	namespace District50\WhatsAppStreamCrypto\Stream;
	
	use Psr\Http\Message\StreamInterface;
	use District50\WhatsAppStreamCrypto\Crypto\KeyExpander;
	use District50\WhatsAppStreamCrypto\Crypto\MediaType;
	use District50\WhatsAppStreamCrypto\Exception\CryptoException;
	use District50\WhatsAppStreamCrypto\Exception\IntegrityException;
	
	/**
	 * Поток для дешифрования данных в формате WhatsApp
	 *
	 * Декоратор для PSR-7 StreamInterface, который дешифрует данные
	 * при чтении с использованием WhatsApp алгоритма
	 */
	class DecryptStream implements StreamInterface
	{
		private StreamInterface $stream;
		private KeyExpander $keyExpander;
		private string $decryptedBuffer = '';
		private int $decryptedPosition = 0;
		private bool $verified = false;
		private ?int $originalSize = null;
		
		/**
		 * Конструктор
		 *
		 * @param StreamInterface $stream Зашифрованный поток
		 * @param string $mediaKey Ключ дешифрования (32 байта)
		 * @param MediaType $mediaType Тип медиа
		 */
		public function __construct(
			StreamInterface $stream,
			string $mediaKey,
			MediaType $mediaType
		) {
			$this->stream = $stream;
			$this->keyExpander = new KeyExpander($mediaKey, $mediaType);
		}
		
		/**
		 * {@inheritdoc}
		 */
		public function __toString(): string
		{
			try {
				$this->verifyAndDecrypt();
				return $this->decryptedBuffer;
			} catch (\Throwable $e) {
				return '';
			}
		}
		
		/**
		 * {@inheritdoc}
		 */
		public function close(): void
		{
			$this->stream->close();
			$this->decryptedBuffer = '';
			$this->verified = false;
		}
		
		/**
		 * {@inheritdoc}
		 */
		public function detach()
		{
			$this->close();
			return null;
		}
		
		/**
		 * {@inheritdoc}
		 */
		public function getSize(): ?int
		{
			if ($this->originalSize === null) {
				$this->verifyAndDecrypt();
			}
			return $this->originalSize;
		}
		
		/**
		 * {@inheritdoc}
		 */
		public function tell(): int
		{
			return $this->decryptedPosition;
		}
		
		/**
		 * {@inheritdoc}
		 */
		public function eof(): bool
		{
			$this->verifyAndDecrypt();
			return $this->decryptedPosition >= strlen($this->decryptedBuffer);
		}
		
		/**
		 * {@inheritdoc}
		 */
		public function isSeekable(): bool
		{
			return true;
		}
		
		/**
		 * {@inheritdoc}
		 */
		public function seek($offset, $whence = SEEK_SET): void
		{
			$this->verifyAndDecrypt();
			$length = strlen($this->decryptedBuffer);
			
			switch ($whence) {
				case SEEK_SET:
					$newPos = $offset;
					break;
				case SEEK_CUR:
					$newPos = $this->decryptedPosition + $offset;
					break;
				case SEEK_END:
					$newPos = $length + $offset;
					break;
				default:
					throw new \RuntimeException('Invalid whence value');
			}
			
			if ($newPos < 0 || $newPos > $length) {
				throw new \RuntimeException('Seek position out of bounds');
			}
			
			$this->decryptedPosition = $newPos;
		}
		
		/**
		 * {@inheritdoc}
		 */
		public function rewind(): void
		{
			$this->seek(0);
		}
		
		/**
		 * {@inheritdoc}
		 */
		public function isWritable(): bool
		{
			return false;
		}
		
		/**
		 * {@inheritdoc}
		 */
		public function write($string): int
		{
			throw new \RuntimeException('DecryptStream is not writable');
		}
		
		/**
		 * {@inheritdoc}
		 */
		public function isReadable(): bool
		{
			return true;
		}
		
		/**
		 * {@inheritdoc}
		 */
		public function read($length): string
		{
			$this->verifyAndDecrypt();
			
			$result = substr($this->decryptedBuffer, $this->decryptedPosition, $length);
			$this->decryptedPosition += strlen($result);
			
			return $result;
		}
		
		/**
		 * {@inheritdoc}
		 */
		public function getContents(): string
		{
			$this->verifyAndDecrypt();
			$contents = substr($this->decryptedBuffer, $this->decryptedPosition);
			$this->decryptedPosition = strlen($this->decryptedBuffer);
			return $contents;
		}
		
		/**
		 * {@inheritdoc}
		 */
		public function getMetadata($key = null)
		{
			$metadata = $this->stream->getMetadata();
			if ($key === null) {
				return $metadata;
			}
			
			return $metadata[$key] ?? null;
		}
		
		/**
		 * Проверяет MAC и дешифрует данные
		 */
		private function verifyAndDecrypt(): void
		{
			if ($this->verified) {
				return;
			}
			
			// Получаем все данные из потока
			$encryptedData = $this->stream->getContents();
			$dataLength = strlen($encryptedData);
			
			if ($dataLength < 10) {
				throw IntegrityException::macMismatch();
			}
			
			// Разделяем на зашифрованные данные и MAC
			$file = substr($encryptedData, 0, -10);
			$mac = substr($encryptedData, -10);
			
			// Проверяем HMAC
			$iv = $this->keyExpander->getIv();
			$macData = $iv . $file;
			$expectedHmac = hash_hmac('sha256', $macData, $this->keyExpander->getMacKey(), true);
			$expectedMac = substr($expectedHmac, 0, 10);
			
			if (!hash_equals($expectedMac, $mac)) {
				throw IntegrityException::macMismatch();
			}
			
			// Дешифруем
			$decrypted = openssl_decrypt(
				$file,
				'aes-256-cbc',
				$this->keyExpander->getCipherKey(),
				OPENSSL_RAW_DATA,
				$iv
			);
			
			if ($decrypted === false) {
				throw CryptoException::decryptionFailed(openssl_error_string());
			}
			
			// Удаляем PKCS#7 padding
			$padding = ord($decrypted[strlen($decrypted) - 1]);
			if ($padding < 1 || $padding > 16) {
				throw CryptoException::decryptionFailed('Invalid padding');
			}
			
			$this->decryptedBuffer = substr($decrypted, 0, -$padding);
			$this->originalSize = strlen($this->decryptedBuffer);
			$this->verified = true;
		}
	}