<?php
	namespace District50\WhatsAppStreamCrypto\Stream;
	
	use Psr\Http\Message\StreamInterface;
	use District50\WhatsAppStreamCrypto\Crypto\KeyExpander;
	use District50\WhatsAppStreamCrypto\Crypto\MediaType;
	use District50\WhatsAppStreamCrypto\Exception\CryptoException;
	
	/**
	 * Поток для шифрования данных в формате WhatsApp
	 *
	 * Декоратор для PSR-7 StreamInterface, который шифрует данные
	 * при записи/чтении с использованием WhatsApp алгоритма
	 */
	class EncryptStream implements StreamInterface {
		private StreamInterface $stream;
		private KeyExpander $keyExpander;
		private string $buffer = '';
		private bool $finalized = false;
		private bool $macWritten = false;
		private string $encryptedData = '';
		
		/**
		 * Конструктор
		 *
		 * @param StreamInterface $stream Оригинальный поток
		 * @param string $mediaKey Ключ шифрования (32 байта)
		 * @param MediaType $mediaType Тип медиа
		 */
		public function __construct(
			StreamInterface $stream,
			string $mediaKey,
			MediaType $mediaType
		) {
			$this->stream = $stream;
			$this->keyExpander = new KeyExpander( $mediaKey, $mediaType );
		}
		
		/**
		 * {@inheritdoc}
		 */
		public function __toString(): string {
			try {
				$this->finalize();
				return $this->encryptedData;
			} catch( \Throwable $e ) {
				return '';
			}
		}
		
		/**
		 * {@inheritdoc}
		 */
		public function close(): void {
			$this->stream->close();
			$this->buffer = '';
			$this->encryptedData = '';
			$this->finalized = false;
			$this->macWritten = false;
		}
		
		/**
		 * {@inheritdoc}
		 */
		public function detach() {
			$this->close();
			return null;
		}
		
		/**
		 * {@inheritdoc}
		 */
		public function getSize(): ?int {
			if( $this->finalized ) {
				return strlen( $this->encryptedData );
			}
			
			$originalSize = $this->stream->getSize();
			if( $originalSize === null ) {
				return null;
			}
			
			// Размер зашифрованных данных с учетом padding и MAC (10 байт)
			$paddedSize = $this->getPaddedSize( $originalSize );
			return $paddedSize + 10;
		}
		
		/**
		 * {@inheritdoc}
		 */
		public function tell(): int {
			if( $this->finalized ) {
				return $this->stream->tell();
			}
			return $this->stream->tell();
		}
		
		/**
		 * {@inheritdoc}
		 */
		public function eof(): bool {
			return $this->finalized && $this->stream->eof();
		}
		
		/**
		 * {@inheritdoc}
		 */
		public function isSeekable(): bool {
			return false; // Зашифрованный поток не поддерживает произвольный доступ
		}
		
		/**
		 * {@inheritdoc}
		 */
		public function seek( $offset, $whence = SEEK_SET ): void {
			throw new \RuntimeException( 'EncryptStream is not seekable' );
		}
		
		/**
		 * {@inheritdoc}
		 */
		public function rewind(): void {
			throw new \RuntimeException( 'EncryptStream is not rewindable' );
		}
		
		/**
		 * {@inheritdoc}
		 */
		public function isWritable(): bool {
			return $this->stream->isWritable();
		}
		
		/**
		 * {@inheritdoc}
		 */
		public function write( $string ): int {
			if( $this->finalized ) {
				throw new CryptoException( 'Cannot write to finalized stream' );
			}
			
			$this->buffer .= $string;
			return strlen( $string );
		}
		
		/**
		 * {@inheritdoc}
		 */
		public function isReadable(): bool {
			return $this->stream->isReadable();
		}
		
		/**
		 * {@inheritdoc}
		 */
		public function read( $length ): string {
			if( !$this->finalized ) {
				$this->finalize();
			}
			
			$result = substr( $this->encryptedData, $this->stream->tell(), $length );
			$this->stream->seek( $this->stream->tell() + strlen( $result ) );
			
			return $result;
		}
		
		/**
		 * {@inheritdoc}
		 */
		public function getContents(): string {
			$this->finalize();
			$contents = $this->encryptedData;
			$this->encryptedData = '';
			return $contents;
		}
		
		/**
		 * {@inheritdoc}
		 */
		public function getMetadata( $key = null ) {
			$metadata = $this->stream->getMetadata();
			if( $key === null ) {
				return $metadata;
			}
			
			return $metadata[ $key ] ?? null;
		}
		
		/**
		 * Финализирует шифрование: применяет AES-CBC с padding и добавляет MAC
		 */
		private function finalize(): void {
			if( $this->finalized ) {
				return;
			}
			
			// Добавляем PKCS#7 padding
			$blockSize = 16;
			$data = $this->buffer;
			$padding = $blockSize - ( strlen( $data ) % $blockSize );
			$data .= str_repeat( chr( $padding ), $padding );
			
			// Шифруем AES-CBC
			$encrypted = openssl_encrypt(
				$data,
				'aes-256-cbc',
				$this->keyExpander->getCipherKey(),
				OPENSSL_RAW_DATA,
				$this->keyExpander->getIv()
			);
			
			if( $encrypted === false ) {
				throw CryptoException::encryptionFailed( openssl_error_string() );
			}
			
			// Вычисляем HMAC для iv + encrypted
			$iv = $this->keyExpander->getIv();
			$macData = $iv . $encrypted;
			$hmac = hash_hmac( 'sha256', $macData, $this->keyExpander->getMacKey(), true );
			$mac = substr( $hmac, 0, 10 ); // Первые 10 байт
			
			// Сохраняем результат
			$this->encryptedData = $encrypted . $mac;
			$this->finalized = true;
		}
		
		/**
		 * Вычисляет размер с padding для PKCS#7
		 */
		private function getPaddedSize( int $size ): int {
			$blockSize = 16;
			$padding = $blockSize - ( $size % $blockSize );
			return $size + $padding;
		}
	}