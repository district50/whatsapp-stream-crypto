<?php
	
	namespace District50\WhatsAppStreamCrypto\Tests\Stream;
	
	use PHPUnit\Framework\TestCase;
	use GuzzleHttp\Psr7\Utils;
	use District50\WhatsAppStreamCrypto\Stream\SidecarGenerator;
	use District50\WhatsAppStreamCrypto\Crypto\MediaType;
	
	class SidecarGeneratorTest extends TestCase {
		private string $mediaKey;
		
		protected function setUp(): void {
			$this->mediaKey = str_repeat( 's', 32 );
		}
		
		public function testGenerateSidecar(): void {
			$testData = str_repeat( 'A', 200 * 1024 ); // 200KB данных
			$originalStream = Utils::streamFor( $testData );
			
			$sidecar = SidecarGenerator::generate( $originalStream, $this->mediaKey, MediaType::VIDEO );
			
			// Проверяем, что sidecar имеет ожидаемый размер
			$expectedMacCount = ceil( strlen( $testData ) / 65536 );
			$expectedSize = $expectedMacCount * 10;
			
			$this->assertEquals( $expectedSize, strlen( $sidecar ) );
		}
		
		public function testGenerateFromData(): void {
			$testData = str_repeat( 'B', 150 * 1024 );
			
			$sidecar1 = SidecarGenerator::generateFromData( $testData, $this->mediaKey, MediaType::AUDIO );
			$sidecar2 = SidecarGenerator::generateFromData( $testData, $this->mediaKey, MediaType::AUDIO );
			
			$this->assertEquals( $sidecar1, $sidecar2 );
		}
		
		public function testSidecarConsistency(): void {
			$testData = str_repeat( 'C', 100 * 1024 );
			$originalStream = Utils::streamFor( $testData );
			
			$sidecarFromStream = SidecarGenerator::generate( $originalStream, $this->mediaKey, MediaType::VIDEO );
			$sidecarFromData = SidecarGenerator::generateFromData( $testData, $this->mediaKey, MediaType::VIDEO );
			
			$this->assertEquals( $sidecarFromStream, $sidecarFromData );
		}
		
		public function testSidecarForDifferentMediaTypes(): void {
			$testData = str_repeat( 'D', 100 * 1024 );
			
			$sidecarVideo = SidecarGenerator::generateFromData( $testData, $this->mediaKey, MediaType::VIDEO );
			$sidecarAudio = SidecarGenerator::generateFromData( $testData, $this->mediaKey, MediaType::AUDIO );
			
			$this->assertNotEquals( $sidecarVideo, $sidecarAudio );
		}
	}