<?php
	
	namespace District50\WhatsAppStreamCrypto\Tests\Stream;
	
	use PHPUnit\Framework\TestCase;
	use GuzzleHttp\Psr7\Stream;
	use GuzzleHttp\Psr7\Utils;
	use District50\WhatsAppStreamCrypto\Stream\EncryptStream;
	use District50\WhatsAppStreamCrypto\Stream\DecryptStream;
	use District50\WhatsAppStreamCrypto\Crypto\MediaType;
	
	class EncryptDecryptTest extends TestCase {
		private string $testData;
		private string $mediaKey;
		
		protected function setUp(): void {
			$this->testData = 'This is test data for encryption and decryption test. ' .
				'It should be properly encrypted and then decrypted back. ' .
				str_repeat( 'X', 1000 );
			$this->mediaKey = str_repeat( 'k', 32 );
		}
		
		public function testEncryptThenDecrypt(): void {
			// Создаем оригинальный поток
			$originalStream = Utils::streamFor( $this->testData );
			
			// Шифруем
			$encryptedStream = new EncryptStream( $originalStream, $this->mediaKey, MediaType::DOCUMENT );
			$encryptedData = $encryptedStream->getContents();
			
			// Проверяем, что зашифрованные данные отличаются от оригинальных
			$this->assertNotEquals( $this->testData, $encryptedData );
			
			// Создаем поток с зашифрованными данными
			$encryptedStreamForDecrypt = Utils::streamFor( $encryptedData );
			
			// Дешифруем
			$decryptStream = new DecryptStream( $encryptedStreamForDecrypt, $this->mediaKey, MediaType::DOCUMENT );
			$decryptedData = $decryptStream->getContents();
			
			// Проверяем, что данные совпали
			$this->assertEquals( $this->testData, $decryptedData );
		}
		
		public function testEncryptWithWrongKey(): void {
			$originalStream = Utils::streamFor( $this->testData );
			
			$encryptedStream = new EncryptStream( $originalStream, $this->mediaKey, MediaType::IMAGE );
			$encryptedData = $encryptedStream->getContents();
			
			$wrongKey = str_repeat( 'w', 32 );
			$encryptedStreamForDecrypt = Utils::streamFor( $encryptedData );
			
			$this->expectException( \YourVendor\WhatsAppStreamCrypto\Exception\IntegrityException::class );
			
			$decryptStream = new DecryptStream( $encryptedStreamForDecrypt, $wrongKey, MediaType::IMAGE );
			$decryptStream->getContents();
		}
		
		public function testReadChunked(): void {
			$originalStream = Utils::streamFor( $this->testData );
			$encryptedStream = new EncryptStream( $originalStream, $this->mediaKey, MediaType::VIDEO );
			
			// Читаем по частям
			$chunks = [];
			while( !$encryptedStream->eof() ) {
				$chunks[] = $encryptedStream->read( 100 );
			}
			
			$encryptedData = implode( '', $chunks );
			
			$encryptedStreamForDecrypt = Utils::streamFor( $encryptedData );
			$decryptStream = new DecryptStream( $encryptedStreamForDecrypt, $this->mediaKey, MediaType::VIDEO );
			
			$decryptedData = '';
			while( !$decryptStream->eof() ) {
				$decryptedData .= $decryptStream->read( 100 );
			}
			
			$this->assertEquals( $this->testData, $decryptedData );
		}
		
		public function testSeekInDecryptedStream(): void {
			$originalStream = Utils::streamFor( $this->testData );
			$encryptedStream = new EncryptStream( $originalStream, $this->mediaKey, MediaType::AUDIO );
			$encryptedData = $encryptedStream->getContents();
			
			$encryptedStreamForDecrypt = Utils::streamFor( $encryptedData );
			$decryptStream = new DecryptStream( $encryptedStreamForDecrypt, $this->mediaKey, MediaType::AUDIO );
			
			// Читаем первые 10 байт
			$first10 = $decryptStream->read( 10 );
			$this->assertEquals( substr( $this->testData, 0, 10 ), $first10 );
			
			// Перемещаемся в конец
			$decryptStream->seek( -5, SEEK_END );
			$last5 = $decryptStream->read( 5 );
			$this->assertEquals( substr( $this->testData, -5 ), $last5 );
			
			// Перемещаемся в начало
			$decryptStream->rewind();
			$fullData = $decryptStream->getContents();
			$this->assertEquals( $this->testData, $fullData );
		}
	}