<?php
	
	namespace District50\WhatsAppStreamCrypto\Tests\Crypto;
	
	use PHPUnit\Framework\TestCase;
	use District50\WhatsAppStreamCrypto\Crypto\KeyExpander;
	use District50\WhatsAppStreamCrypto\Crypto\MediaType;
	
	class KeyExpanderTest extends TestCase {
		public function testKeyExpanderWithValidKey(): void {
			$mediaKey = str_repeat( 'a', 32 );
			$expander = new KeyExpander( $mediaKey, MediaType::IMAGE );
			
			$this->assertEquals( 16, strlen( $expander->getIv() ) );
			$this->assertEquals( 32, strlen( $expander->getCipherKey() ) );
			$this->assertEquals( 32, strlen( $expander->getMacKey() ) );
			$this->assertEquals( 32, strlen( $expander->getRefKey() ) );
		}
		
		public function testKeyExpanderWithInvalidKeyLength(): void {
			$this->expectException( \InvalidArgumentException::class );
			new KeyExpander( 'too short', MediaType::IMAGE );
		}
		
		public function testDifferentMediaTypes(): void {
			$mediaKey = str_repeat( 'b', 32 );
			
			$imageExpander = new KeyExpander( $mediaKey, MediaType::IMAGE );
			$videoExpander = new KeyExpander( $mediaKey, MediaType::VIDEO );
			
			$this->assertNotEquals( $imageExpander->getIv(), $videoExpander->getIv() );
			$this->assertNotEquals( $imageExpander->getCipherKey(), $videoExpander->getCipherKey() );
		}
	}